#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build the community frontend/backend and push its container image to private AWS ECR.

Usage: ./build.sh [options]

Options:
  --region REGION          AWS region (default: ap-southeast-1; AWS env overrides)
  --profile PROFILE        AWS CLI profile (default: AWS_PROFILE or credential chain)
  --repository NAME        ECR repository (default: mizuumi-sandbox-signoz-community)
  --tag TAG                Image tag (default: UTC timestamp, Git SHA, dirty marker)
  --platform PLATFORMS     linux/amd64, linux/arm64, or both comma-separated
                           (default: linux/amd64)
  --create-repository      Create the repository if it does not exist
  --dry-run                Print the build/push plan without building or calling AWS
  -h, --help               Show help

Environment: ECR_REPOSITORY, IMAGE_TAG, PLATFORMS, AWS_PROFILE, AWS_REGION,
             AWS_DEFAULT_REGION, AWS_ACCOUNT_ID (expected account; default: 634740393758),
             GOTOOLCHAIN (default: version from go.mod), PNPM_VERSION (default: 10.34.9).

Examples:
  ./build.sh --dry-run
  ./build.sh --profile dev --tag oidc-v1
  ./build.sh --platform linux/amd64,linux/arm64

Requires Go, Node.js >=22, npx, make, Git, AWS CLI v2, and Docker with Buildx.
Buildx must support the selected platforms. This publishes an image; it does not
update ECS, EKS, IAM, or running workloads. No OIDC secrets are included in the image.
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
require_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "$1 requires a value"; }
run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if [[ $dry_run == false ]]; then "$@"; fi
}

region=${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-southeast-1}}
profile=${AWS_PROFILE:-}
repository=${ECR_REPOSITORY:-mizuumi-sandbox-signoz-community}
expected_account=${AWS_ACCOUNT_ID:-634740393758}
tag=${IMAGE_TAG:-}
platforms=${PLATFORMS:-linux/amd64}
create_repository=false
dry_run=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region) require_value "$@"; region=$2; shift 2 ;;
    --profile) require_value "$@"; profile=$2; shift 2 ;;
    --repository) require_value "$@"; repository=$2; shift 2 ;;
    --tag) require_value "$@"; tag=$2; shift 2 ;;
    --platform) require_value "$@"; platforms=$2; shift 2 ;;
    --create-repository) create_repository=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[[ -n $region ]] || die "set --region, AWS_REGION, or AWS_DEFAULT_REGION"
[[ $region =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || die "invalid AWS region: $region"
[[ $repository =~ ^[a-z0-9]+([._/-][a-z0-9]+)*$ && ${#repository} -le 256 ]] || die "invalid ECR repository name"
[[ $expected_account =~ ^[0-9]{12}$ ]] || die "AWS_ACCOUNT_ID must have 12 digits"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$script_dir"
if [[ -z $tag ]]; then
  tag="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD)"
  if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then tag+="-dirty"; fi
fi
[[ $tag =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$ ]] || die "invalid container image tag"

archs=()
IFS=',' read -r -a requested_platforms <<< "$platforms"
for platform in "${requested_platforms[@]}"; do
  case "$platform" in
    linux/amd64) archs+=(amd64) ;;
    linux/arm64) archs+=(arm64) ;;
    *) die "unsupported platform: $platform" ;;
  esac
done
[[ ${#archs[@]} -gt 0 && $platforms != *, ]] || die "provide at least one platform"

go_version=$(awk '$1 == "go" {print $2; exit}' go.mod)
[[ -n $go_version ]] || die "go.mod has no Go version"
export GOTOOLCHAIN=${GOTOOLCHAIN:-go$go_version}
pnpm_version=${PNPM_VERSION:-10.34.9}
[[ $pnpm_version =~ ^10\.[0-9]+\.[0-9]+$ ]] || die "PNPM_VERSION must be an exact pnpm 10 version"
aws_cmd=(aws --no-cli-pager --region "$region")
if [[ -n $profile ]]; then aws_cmd+=(--profile "$profile"); fi

if [[ $dry_run == true ]]; then
  suffix=amazonaws.com
  if [[ $region == cn-* ]]; then suffix=amazonaws.com.cn; fi
  repository_uri="$expected_account.dkr.ecr.$region.$suffix/$repository"
  run "${aws_cmd[@]}" sts get-caller-identity --query Account --output text
  run "${aws_cmd[@]}" ecr describe-repositories --repository-names "$repository" --query 'repositories[0].repositoryUri' --output text
  if [[ $create_repository == true ]]; then
    printf 'If the repository is missing:\n'
    run "${aws_cmd[@]}" ecr create-repository --repository-name "$repository" --image-tag-mutability IMMUTABLE --image-scanning-configuration scanOnPush=true
  fi
else
  for tool in go node npx make git aws docker; do
    command -v "$tool" >/dev/null || die "required command not found: $tool"
  done
  node -e 'if (Number(process.versions.node.split(".")[0]) < 22) process.exit(1)' || die "Node.js >=22 is required"
  docker info >/dev/null
  docker buildx version >/dev/null
  account_id=$("${aws_cmd[@]}" sts get-caller-identity --query Account --output text)
  [[ $account_id =~ ^[0-9]{12}$ ]] || die "AWS returned an invalid account ID"
  if [[ $account_id != "$expected_account" ]]; then die "authenticated AWS account does not match expected account $expected_account"; fi
  ecr_error=$(mktemp)
  trap 'rm -f "$ecr_error"' EXIT
  if repository_uri=$("${aws_cmd[@]}" ecr describe-repositories --repository-names "$repository" --query 'repositories[0].repositoryUri' --output text 2>"$ecr_error"); then
    :
  elif [[ $create_repository == true && $(cat "$ecr_error") == *RepositoryNotFoundException* ]]; then
    repository_uri=$("${aws_cmd[@]}" ecr create-repository --repository-name "$repository" --image-tag-mutability IMMUTABLE --image-scanning-configuration scanOnPush=true --query 'repository.repositoryUri' --output text)
  else
    cat "$ecr_error" >&2
    die "cannot access ECR repository; use --create-repository only if it is missing"
  fi
  [[ $repository_uri == "$account_id.dkr.ecr.$region."*"/$repository" ]] || die "unexpected ECR repository URI"
fi

image="$repository_uri:$tag"
printf 'Community image: %s\nPlatforms: %s\nGo toolchain: %s\n' "$image" "$platforms" "$GOTOOLCHAIN"
run env CI=1 npx --yes "pnpm@$pnpm_version" --dir frontend install --frozen-lockfile
run env CI=1 npx --yes "pnpm@$pnpm_version" --dir frontend build
run env CGO_ENABLED=0 make go-build-community OS=linux "ARCHS=${archs[*]}" "VERSION=$tag"

if [[ $dry_run == false ]]; then
  for arch in "${archs[@]}"; do
    dependencies=$(CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go list -tags timetzdata -deps ./cmd/community)
    if [[ $dependencies == *github.com/SigNoz/signoz/ee/* || $dependencies == *github.com/SigNoz/signoz/cmd/enterprise* ]]; then
      die "community build unexpectedly imports enterprise packages"
    fi
  done
fi

registry=${repository_uri%%/*}
printf 'Authenticating Docker to %s using AWS password-stdin.\n' "$registry"
if [[ $dry_run == false ]]; then
  "${aws_cmd[@]}" ecr get-login-password | docker login --username AWS --password-stdin "$registry"
fi
run docker buildx build --platform "$platforms" --file cmd/community/Dockerfile --tag "$image" --push .

if [[ $dry_run == true ]]; then
  printf 'Dry run complete; no build or AWS calls were made.\n'
else
  digest=$("${aws_cmd[@]}" ecr describe-images --repository-name "$repository" --image-ids "imageTag=$tag" --query 'imageDetails[0].imageDigest' --output text)
  [[ $digest == sha256:* ]] || die "ECR did not return a pushed image digest"
  printf 'Published: %s\nDigest: %s@%s\n' "$image" "$repository_uri" "$digest"
fi

# SecAudit — deterministic security audit, zero runtime dependencies.
#
#   docker build -t secaudit .
#   docker run --rm -v "$PWD:/src:ro" secaudit /src --min high
#
# The source mount is read-only and the container runs as a non-root user. A scanner has no
# reason to modify what it is scanning, and the only way to be sure of that is to remove the
# capability rather than to promise it.
#
# BASE IMAGE PINNING. Both stages are pinned to an immutable digest, resolved from the
# registry rather than written from memory — a tag can be repointed, which is the
# SEC-CI-MUTABLE-ACTION class this tool reports on other people's repositories, and a digest
# typed from recall is worse than a tag because it is unverifiable and fails at build time.
# The digest below is `python:3.12-slim-bookworm` as published. To re-resolve on a bump:
#
#   docker pull python:3.13-slim-trixie
#   docker inspect --format='{{index .RepoDigests 0}}' python:3.13-slim-trixie
#
# Keep the `# python:<tag>` comment on each FROM: a bare digest tells a reader nothing about
# which image it is, and the comment is what makes the pin reviewable.
FROM python@sha256:297cf11d0b98b38ac26a56136f0279df845314bcd0347c1f6383fee6e75125ee AS build   # python:3.12-slim-bookworm

WORKDIR /build
COPY kit/ ./kit/
RUN python3 -m pip install --no-cache-dir --upgrade build && \
    python3 -m build kit --outdir /dist

# The wheel must add nothing to a user's dependency tree. Asserted here as well as in the
# release workflow, because this image is a separate artefact somebody can build without ever
# running that workflow — and an invariant checked in only one of two paths is not one.
COPY scripts/assert_no_runtime_deps.py /build/
RUN python3 /build/assert_no_runtime_deps.py /dist

FROM python@sha256:297cf11d0b98b38ac26a56136f0279df845314bcd0347c1f6383fee6e75125ee   # python:3.12-slim-bookworm

# `git` is here for exactly one reason: `--since <ref>` materialises the baseline tree with
# `git archive`. Without it that flag fails with a clear message instead of silently auditing
# everything and calling a pull request clean.
RUN apt-get update && \
    apt-get install --no-install-recommends -y git && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --create-home --uid 10001 --shell /usr/sbin/nologin secaudit

COPY --from=build /dist/*.whl /tmp/
RUN python3 -m pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Scanning means reading untrusted input. Root is not needed to read a mounted directory.
USER 10001
WORKDIR /src

# git refuses to operate in a directory owned by another user unless it is marked safe, and a
# bind mount from the host is exactly that case. Without this, `--since` fails with a confusing
# ownership error that has nothing to do with the audit. Scoped to config env vars rather than
# written into a global gitconfig so it applies to this process and leaves no file behind.
ENV GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=safe.directory \
    GIT_CONFIG_VALUE_0=*

ENTRYPOINT ["secaudit"]
CMD ["--help"]

LABEL org.opencontainers.image.title="SecAudit" \
      org.opencontainers.image.description="Deterministic security audit: taint analysis, dependency reachability (VEX), SBOM and compliance evidence. Zero runtime dependencies." \
      org.opencontainers.image.source="https://github.com/mtvrkan/secaudit" \
      org.opencontainers.image.licenses="MIT"

# A reviewer should be able to evaluate this software in one command, without
# a Python environment, a Solidity toolchain or a blockchain node.
#
#   docker build -t ledgerguard .
#   docker run --rm ledgerguard                 # run the test suite
#   docker run --rm ledgerguard demo            # the narrated walkthrough
#   docker run --rm ledgerguard bench           # detection rates
#   docker run --rm -v "$PWD/out:/out" ledgerguard experiments
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
COPY tests/ ./tests/
COPY scripts/ ./scripts/
COPY contracts/ ./contracts/
COPY demo.py ./
COPY examples/ ./examples/

RUN pip install --no-cache-dir -e ".[dev]"

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["test"]

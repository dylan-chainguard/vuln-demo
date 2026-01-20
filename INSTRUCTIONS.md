# Instructions

## Starting the demo app

```
# build all images
./scripts/build-images.sh

# run main demo app
docker-compose up

# run grafana
cd monitoring
docker-compose up

# load db with demo data
python3 scripts/reset-database.py
```

Visit: http://localhost:3001/d/baseline-chainguard-comparison/baseline-vs-chainguard-comparison

Make a Pull Request like this: https://github.com/dylan-chainguard/vuln-demo/pull/3

After merging, wait for CI to complete then run:

```
./scripts/get-latest-results-from-github.sh
```

## Resetting the demo

```
# Reset db
python3 scripts/reset-database.py

# Revert main branch
git revert <insert commit id>
git push
```
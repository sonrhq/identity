#!/usr/bin/env bash

set -e


cd proto
echo "Generating gogo proto code"
proto_dirs=$(find . -path -prune -o -name '*.proto' -print0 | xargs -0 -n1 dirname | sort | uniq)
for dir in $proto_dirs; do
  for file in $(find "${dir}" -maxdepth 1 -name '*.proto'); do
    if grep -q "option go_package" "$file" && grep -H -o -c 'option go_package.*github.com/sonrhq/identity/api' "$file" | grep -q ':0$'; then
      buf generate --template buf.gen.gogo.yaml $file
    fi
  done
done

echo "Generating pulsar proto code"
proto_dirs=$(find . -path -prune -o -name '*.proto' -print0 | xargs -0 -n1 dirname | sort | uniq)
for dir in $proto_dirs; do
  for file in $(find "${dir}" -maxdepth 1 -name '*.proto'); do
    if grep -q "option go_package" "$file" && grep -H -o -c 'option go_package.*github.com/sonrhq/identity/api' "$file" | grep -q ':0$'; then
      buf generate --template buf.gen.pulsar.yaml
    fi
  done
done

echo "Generating orm code"
proto_dirs=$(find . -path -prune -o -name '*.proto' -print0 | xargs -0 -n1 dirname | sort | uniq)
for dir in $proto_dirs; do
  for file in $(find "${dir}" -maxdepth 1 -name 'state.proto'); do
      buf generate --template buf.gen.proto.yaml
      buf generate --template buf.gen.yaml
  done
done

cd ..

# Find and delete uncompatible proto implementations
find . -name 'state_query.pulsar.go' -delete
find . -name 'state.pulsar.go' -delete
find . -name 'identifier.pb.go' -delete
find . -name 'module.pb.go' -delete
find . -name 'query.pb.go' -delete
find . -name 'tx.pb.go' -delete
find . -name 'types.pb.go' -delete

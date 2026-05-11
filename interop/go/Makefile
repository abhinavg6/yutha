# Regenerate Go bindings and run the differential test.
#
# Toolchain prereqs:
#   protoc            (brew install protobuf)
#   protoc-gen-go     (go install google.golang.org/protobuf/cmd/protoc-gen-go@latest)

PROTOC    ?= protoc
PROTO_DIR := ../../spec
GO_OUT    := gen
MODULE    := github.com/yutha/yutha/interop/go/gen

.PHONY: regen test all check-tools

check-tools:
	@command -v $(PROTOC) >/dev/null 2>&1 || { \
		echo "ERROR: protoc not found. Install: brew install protobuf"; exit 1; }
	@command -v protoc-gen-go >/dev/null 2>&1 || { \
		echo "ERROR: protoc-gen-go not found. Install: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"; \
		echo "       Then ensure \$$(go env GOPATH)/bin is on PATH."; exit 1; }

regen: check-tools
	@mkdir -p $(GO_OUT)
	$(PROTOC) \
		-I $(PROTO_DIR) \
		--go_out=$(GO_OUT) \
		--go_opt=module=$(MODULE) \
		--go_opt=Mcommon.proto=$(MODULE)/yutha/common/v1 \
		--go_opt=Mreceipt/receipt-v1.proto=$(MODULE)/yutha/receipt/v1 \
		--go_opt=Mpassport/passport-v1.proto=$(MODULE)/yutha/passport/v1 \
		--go_opt=Menvelope/envelope-v1.proto=$(MODULE)/yutha/envelope/v1 \
		--go_opt=Mcapability/capability-v1.proto=$(MODULE)/yutha/capability/v1 \
		$(PROTO_DIR)/common.proto \
		$(PROTO_DIR)/receipt/receipt-v1.proto \
		$(PROTO_DIR)/passport/passport-v1.proto \
		$(PROTO_DIR)/envelope/envelope-v1.proto \
		$(PROTO_DIR)/capability/capability-v1.proto
	@echo "Generated Go bindings under ./$(GO_OUT)/"

test:
	go test ./...

all: regen test

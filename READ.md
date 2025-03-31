
protoc --go_out=. --go_opt=paths=source_relative     --go-grpc_out=. --go-grpc_opt=paths=source_relative     auth.proto

mockery --name=Repository --output=./mocks --outpkg=mocks --case=underscore
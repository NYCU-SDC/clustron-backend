[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/NYCU-SDC/clustron-backend)
# clustron-backend
This is the backend of NYCU SDC Clustron Project. 

We aim to create a service to visuallize the LDAP access managing, Slurm operation, and resource usage on remote computer cluster.

# Get Started
## Install Go
Follow the [official installation guide](https://go.dev/doc/install).
Choose version 1.24 if you would like to specify the Go version.

## Clone the repository
Open your terminal and navigate to the directory that you wish to put this project.

And then execute the following command: 
```
git clone https://github.com/NYCU-SDC/clustron-backend.git
cd  clustron-backend
git fetch
```

## Install necessary dependencies
### Install Go packages
```
make prepare
```
Be sure you have `make` installed. You can check by:
```
make -v
```
If the result is something like `make command not found`, install `make` before running the above command.

### Install other tools
We use [sqlc](https://sqlc.dev) for database queries generation and [mockery](https://vektra.github.io/mockery/latest/) for mocking.

#### MacOS
```
brew install sqlc

brew install mockery
brew upgrade mockery
```
#### Go install 
```
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
go install github.com/vektra/mockery/v3@v3.2.2      # not recommanded by the documentation
```

You can also find more OS-spacific installing methods from the documentation.

## Run the backend
You can simply start the backend service via command:
```
make run
```

## Build the backend
To build the backend code into binary, run:
```
make build
```
The binary file will be `./bin/backend`.

## Pre-push hook (Optional)
We recommand you enable the pre-push hook if wish to commit to this repository.
This will run checks before the code is pushed to the remote.

The pre-push hook is run via [lefthook](https://lefthook.dev).

### MacOS
```
brew install lefthook
```
### Go install 
```
go install github.com/evilmartians/lefthook@latest
```
You can also find more OS-spacific installing methods from the documentation.

After installed lefthook, update git hook to use lefthook:
```
# run at project root
left hook install
```
Then you are good to go!
The pre-push checks will be envoked when you do `git push`.

If the checks didn't pass, the push will be blocked.

To temporary by pass the pre-push check and push:
```
git push origin --no-verify
```
To disable pre-push action until re-open it:
```
left hook uninstall
```

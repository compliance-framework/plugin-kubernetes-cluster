# Compliance Framework Plugin Template

This is a template for building a compliance framework plugin.

Inspect main.go for a detailed description of how to build the plugin.

## Prerequisites

* GoReleaser https://goreleaser.com/install/

## Building

Once you are ready to serve the plugin, you need to build the binaries which can be used by the agent.

```shell
goreleaser release --snapshot --clean
```

## Usage

You can use this plugin by passing it to the compliiance agent

```shell
agent --plugin=[PATH_TO_YOUR_BINARY]
```

## Releasing

This plugin is released using goreleaser to build binaries, and Docker to build OCI artifacts (WIP), which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub releases page.

You can find the OCI implementations in the GitHub Packages page.

[Not Yet Implemented] To run this plugin with the Compliance Agent, you can specify the release. The agent will take care of pulling the correct binary.

```shell
concom agent --plugin=https://github.com/compliance-framework/plugin-template/releases/tag/0.0.1
```


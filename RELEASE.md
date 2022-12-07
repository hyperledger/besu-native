This document describes how to make releases of Besu Native.

Please see https://besu.hyperledger.org/ to learn more and contact maintainers if you have questions.

# Prepare the release

Make sure the CHANGELOG is up-to-date with the latest changes.

Communicate with Besu maintainers and announce your intention to conduct a release.

# Publish the release

Make a pull request changing [gradle.properties] version to the next best version.

The repository abides loosely to [semver conventions](https://semver.org/).
* Removing a library or API may require a major version increment (0.7.0 -> 1.0.0)
* Adding a new JAR/Library has been done in minor versions increment (0.6.2 -> 0.7.0)
* Adding a function or API to an existing library has been done in double-dot minor version (0.6.1 -> 0.6.2)

# Create the github tag and release

Create a tag with: `git tag VERSION`

Example: `git tag 0.6.2`

Push the tag to the repository: `git push origin --tags`

Create the github release associated with the tag. Copy the contents of the CHANGELOG for your version as Github release notes.

# Prepare for next release

Change [gradle.properties] to the next minor version with a `-SNAPSHOT` suffix.

Example: `version=0.6.2-SNAPSHOT`

Add the new version to the [CHANGELOG.md]:

Example: `# 0.6.2-SNAPSHOT`

Open a PR with this change.
# aws_idem

Lightweight implementations of subsets of some AWS Boto3 features.

This toolset is mostly intended for tools that support 
system configuration and management.

All calls are idempotent except as explicitly noted or in
cases where it is impractical. e.g:
* Deletion of KMS keys since deletion is not immediate.


## Installation

`pip3 install .`

## Usage

`from aws_idem.iam import policy`

## Testing

Testing uses [placebo](https://github.com/garnaat/placebo) 
to record and later playback boto3 call output.

The source code (this repo) is required for testing. 

The easiest way to run the tests is using 'nose' at the root of the code tree.

`nosetests`

### To add new tests

*placebo* records calls actual call to boto3 in sequence. So, if tests are added:

* Name them so they fall in the correct sequence - e.g. test\_\<nnn\>\_...
* Delete applicable AWS resources
* Delete the applicable '\_placebo' subdirectory
* Comment out `cls.pill.playback()` in the applicable 'setUpClass' method.
* Uncomment `cls.pill.record()` in the applicable 'setUpClass' method.
* Run all the tests once to collect the placebo output
* Uncomment `cls.pill.playback()` in the applicable 'setUpClass' method.
* Comment out `cls.pill.record()` in the applicable 'setUpClass' method.
* Delete applicable AWS resources

## AWS IAM

### Policies


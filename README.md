# varc (Volatile Artifact Collector) #

### About ###
This tool collects a snapshot of volatile data from a system.
It tells you what is happening on a system, and is of particular use when investigating a security incident.

It creates a zip, which contains a number of differnt pieces of data to understand what is happening on a system:
- Json files e.g. running processes and what network connections they are making
- Memory of running proccesses, on a per-process basis
-- This is also carved to extract log and text data from memory
- Netflow data of active connections
- Binary blob data, e.g. The allocated memory of running processes, along with extracted log events in a log format.
- The contents of open files, for example running binaries

![](docs/varc_demo.gif)

In line with the order of volatility, we collect process memory before anything else. Note that varc, and any other tool that runs inside a system, will impact the memory of a system.

### Using as a library ###

You can install from pip with:
```
pip3 install varc
```
Todo: Submit to pip3
Or alternatively, clone this repository then install with:
```
python3 setup.py install
```

Then call with: 
```
from varc import acquire_system
output_file_path = acquire_system().zip_path
```

### Using as a compiled binary ###
You can find compiled binaries for Windows, Linux and OSX under the Releases tab.

### Example Collections ###
To see the output of this tool, you can download example collections from:

- Windows system (Infected with PlugX) - TODO
- OSX (Infected with x) - TODO
- Linux (Infected with X) - TODO
- Docker (ECS Container, infected with CloudCompromiseSimulator) - TODO
- AWS Lambda (Infected with xmrig) - Done

We will be using these in an upcoming CTF.

### Using the collected data ###
Our free tool [Cado Community Edition](https://www.cadosecurity.com/cado-community-edition/) will happily parse this zip, and display the Json data tables as intended.

Our commercial tool [Cado Response](https://www.cadosecurity.com/platform/) additionally enables you to automatically capture both static and volatile data from systems through Cado Host. By using the API, you can automatically investigate and respond to to detections from third party tools such as an EDR like SentinelOne or a cloud detection tool like GuardDuty.

Here is an example of varc output for a Lambda function running xmrig, viewed in [Cado Community Edition](https://www.cadosecurity.com/cado-community-edition/):
![](docs/varc.png)

### Automation ###
varc significantly simplifies the acquisition and analysis of volatile data.
Whilst it can be used manually on an ad-hoc basis, it is a great match for automatic deployment in response to security detections.
The output of varc is designed to be easily consumed by other tools, in standard json format as much as possible.

A typical process might be:
* A detection is fired from a detection tool
* varc is deployed to collect and identify further activity
* Further remediation actions are taken based on the analysis of varc output

### Why are the collected memory files empty? ###
Process memory collection is not currently supported on OSX.

If you run varc on a Linux system without the Ptrace Kernel capability enabled, you will get empty memory files.
You will still get detailed system output.

For example, in our testing:
* AWS Lambda successfully dumped process memory by default.
* EKS on EC2 successfully dumped process memory by default.
* ECS on Fargate required us to enable [CAP_SYS_PTRACE](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-taskdefinition-kernelcapabilities.html) in our task definition.

### License and Contributing###
We’d love any Pull Requests or Bug Reports!

This is licensed under the GPL. Please contact us if this doesn’t work for your use case - we may be able to alternatively license under a non-copyleft license such as the Apache License. We're friendly!
As this software is licensed under the GPL and used in our commercial product, we ask any contributors to sign a simple Contributor License Agreement (CLA). 



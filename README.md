# EC2-EBS-RDS-Inventory-Tool
Lambda for pulling volume / instance / RDS data from an AWS account

------
Summary
------
This toolset is useful for exporting AWS EC2, EBS, Snapshot, and RDS data. Data can be analysed by any data visualization tool supporting JSON (all of them). When using Quicksight, see my other project for parsing S3 files into corresponding dataset folders.

-------
Record Details
-------

These will vary by record type, but look something like:

'Record-Type': ...

'InstanceId': ...

'Type': ...

'Power-State': ...

'Total EBS Provisioned (GB)': ...

'Attached-Volumes': ...

'Tag': Tag


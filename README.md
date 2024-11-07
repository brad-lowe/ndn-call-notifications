## Overview

This repository hosts a script that sends email notifications to the NDN weekly call mailing list.

A GitHub Actions workflow is configured to run every Thursday at 1 pm, the day before the call. **(Work in progress)**

## Adding issues

Using [the NDN Workspace app](https://ndn-workspace.web.app/), follow the instructions on the main page to connect to the testbed.
After receiving your testbed certificate, go to the **Workspace** tab and click **Convert**. Paste in the following trust anchor:

/8=ndn/8=weekly-call-doc/8=KEY/8=%A0w%E9%88%23%27%D91/8=self/54=%00%00%01%92%CA%C4EN/1=%16u%A9%29%8BM%DA%82%A5%8FR%F2%AB%04-%89a%CF%82%AF%ED%FD%A1%5B%0E%28%F0%23%27%0B%D5%24

You should be connected to the ndn/weekly-call-doc workspace now. Paste in any issues you might have between the %START and %END comments in the Issues.xml file. Do not edit anywhere else.

When the workflow is run, those issues should show up in the weekly call email notification.

## Testing the email script locally

Clone the repository.

Run npm install --legacy-peer-deps

Create a new file **.env** in the project directory, based on .env.sample. Replace each variable with your personal testbed certificates and private keys, and those of the workspace you want to use.

If you are using a different workspace than ndn/weekly-call-doc, go into get_info.ts and replace 'c297195e-87d8-46ee-b475-61aa3d909989' on line 262 with the ID of the file you intend to use for testing.

**Note: this will be updated soon to require a specific file name rather than file ID.**

Set the email address and other email settings you want to use on line 298.

Run ./get_info_testbed.bash to send an email.

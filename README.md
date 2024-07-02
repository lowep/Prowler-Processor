# Prowler-Processor
This solution deploys an AWS Cloud9 instance that will be configured to ingest multiple prowler scans and combine them into one document with the categories presorted and redundant findings removed.

# Detailed Deployment Guide for Prowler Scan Processor

## Part 1: CloudFormation Deployment

1. **Prepare the CloudFormation Template**
   - Save the following CloudFormation template as `prowler_processor_cfn.yaml`:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'CloudFormation template for Prowler Scan Processor Environment'

Resources:
  ProwlerProcessorCloud9:
    Type: AWS::Cloud9::EnvironmentEC2
    Properties:
      Name: ProwlerProcessorEnvironment
      Description: Cloud9 Environment for Prowler Scan Processor
      InstanceType: t3.small
      AutomaticStopTimeMinutes: 30
      ImageId: amazonlinux-2-x86_64
      ConnectionType: CONNECT_SSM

  ProwlerProcessorRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: 
                - ec2.amazonaws.com
                - cloud9.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AWSCloud9User
        - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
      Policies:
        - PolicyName: Cloud9Setup
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - cloudformation:DescribeStackResource
                  - cloudformation:SignalResource
                Resource: "*"

Outputs:
  Cloud9EnvironmentURL:
    Description: URL to access the Cloud9 Environment
    Value: !Sub "https://${AWS::Region}.console.aws.amazon.com/cloud9/ide/${ProwlerProcessorCloud9}"
  Cloud9EnvironmentId:
    Description: ID of the Cloud9 Environment
    Value: !Ref ProwlerProcessorCloud9
```

2. **Deploy the CloudFormation Stack**
   - Log in to your AWS Console and navigate to the CloudFormation service.
   - Click "Create stack" and choose "With new resources (standard)".
   - Under "Specify template", choose "Upload a template file" and upload your `prowler_processor_cfn.yaml` file.
   - Click "Next".
   - Enter a stack name (e.g., "ProwlerProcessorStack") and click "Next".
   - On the "Configure stack options" page, you can leave the defaults or add tags if desired. Click "Next".
   - Review the stack details and click "Create stack".
   - Wait for the stack creation to complete. This may take a few minutes.

3. **Access the Cloud9 Environment**
   - Once the stack creation is complete, go to the "Outputs" tab of your stack.
   - Find the "Cloud9EnvironmentURL" value and click on the URL to open your Cloud9 environment.

## Part 2: Setting Up the Cloud9 Environment

1. **Open the Cloud9 IDE**
   - The Cloud9 IDE should open in a new tab. Wait for it to fully load.

2. **Create the Prowler Processor Directory**
   - In the Cloud9 terminal (bottom pane), run the following commands:
     ```
     mkdir -p ~/environment/prowler_processor/input_scans
     mkdir -p ~/environment/prowler_processor/output
     cd ~/environment/prowler_processor
     ```

3. **Install Required Python Package**
   - In the terminal, run:
     ```
     pip install openpyxl
     ```

4. **Create the Prowler Processor Script**
   - In the left sidebar, right-click on the `prowler_processor` folder and select "New File".
   - Name the file `prowler_processor.py`.
   - Copy and paste the following Python script into the file:

```python
import json
import os
import argparse
from collections import defaultdict
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font, Border, Side, Alignment
from openpyxl.utils import get_column_letter

# Configuration options
RESOURCE_TYPES = []  # Leave empty to include all, or specify types to include
EXCLUDE_CHECK_TYPES = []  # Check types to exclude
MAX_FINDINGS_PER_CHECK = 10  # Maximum number of findings to include per check type

def load_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def process_prowler_scans(file_paths, severity_filter):
    all_findings = defaultdict(list)
    
    for file_path in file_paths:
        print(f"Processing file: {file_path}")  # Added print statement
        data = load_json_file(file_path)
        for finding in data:
            # Apply filters
            severity = finding.get('Severity', '')
            if isinstance(severity, dict):
                severity = severity.get('Label') or next(iter(severity.values()), '')
            severity = str(severity).upper()
            
            if severity[0] not in severity_filter:  # Check only the first letter
                continue
            
            if RESOURCE_TYPES and not any(r.get('Type') in RESOURCE_TYPES for r in finding.get('Resources', [])):
                continue
            
            if any(check_type in finding.get('Types', []) for check_type in EXCLUDE_CHECK_TYPES):
                continue
            
            key = (
                tuple(finding.get('Types', [])),
                finding.get('Title', ''),
                severity
            )
            all_findings[key].append(finding)
    
    # Group similar findings and apply MAX_FINDINGS_PER_CHECK
    grouped_findings = []
    for key, findings in all_findings.items():
        grouped_findings.extend(findings[:MAX_FINDINGS_PER_CHECK])
    
    return grouped_findings

def save_excel_file(data, output_file):
    wb = Workbook()
    ws = wb.active
    ws.title = "Findings"

    fields = ['Severity', 'Title', 'Description', 'Types', 'Resources', 'SchemaVersion', 'ProductFields']
    
    # Header styling
    header_fill = PatternFill(start_color="DDEBF7", end_color="DDEBF7", fill_type="solid")
    header_font = Font(bold=True)
    header_border = Border(bottom=Side(style='medium'))
    
    for col, header in enumerate(fields, start=1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.border = header_border
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
    
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    
    def get_severity(x):
        severity = x.get('Severity', '')
        if isinstance(severity, dict):
            severity = severity.get('Label') or next(iter(severity.values()), '')
        return severity_order.get(str(severity).upper(), 4)
    
    sorted_data = sorted(data, key=get_severity)

    # Alternating row colors
    alt_row_fill = PatternFill(start_color="F2F2F2", end_color="F2F2F2", fill_type="solid")

    for row, finding in enumerate(sorted_data, start=2):
        severity = finding.get('Severity', '')
        if isinstance(severity, dict):
            severity = severity.get('Label') or next(iter(severity.values()), '')
        severity = str(severity).upper()

        # Alternating row color
        row_fill = alt_row_fill if row % 2 == 0 else PatternFill(fill_type=None)

        for col, field in enumerate(fields, start=1):
            value = finding.get(field, '')
            
            if isinstance(value, list):
                if field == 'Resources':
                    # Format Resources field
                    formatted_resources = []
                    for resource in value:
                        resource_str = "Resource:\n"
                        for k, v in resource.items():
                            if k == 'Tags' and isinstance(v, dict):
                                resource_str += f"  {k}:\n"
                                for tag_k, tag_v in v.items():
                                    resource_str += f"    {tag_k}: {tag_v}\n"
                            else:
                                resource_str += f"  {k}: {v}\n"
                        formatted_resources.append(resource_str)
                    value = "\n\n".join(formatted_resources)
                else:
                    value = ', '.join(map(str, value))
            elif isinstance(value, dict):
                if field == 'Severity':
                    value = severity
                else:
                    value = ', '.join([f"{k}: {v}" for k, v in value.items()])
            
            if field == 'Description':
                # Split the description into bullet points using commas
                findings = value.split(', ')
                value = '\n'.join([f"• {finding.strip()}" for finding in findings if finding.strip()])
            
            cell = ws.cell(row=row, column=col, value=value)
            cell.fill = row_fill
            cell.alignment = Alignment(wrap_text=True, vertical='top')

            if field == 'Severity':
                if severity == 'CRITICAL':
                    cell.fill = PatternFill(start_color='FFFF0000', end_color='FFFF0000', fill_type='solid')
                elif severity == 'HIGH':
                    cell.fill = PatternFill(start_color='FFFF9900', end_color='FFFF9900', fill_type='solid')
                elif severity == 'MEDIUM':
                    cell.fill = PatternFill(start_color='FFFFFF00', end_color='FFFFFF00', fill_type='solid')
                elif severity == 'LOW':
                    cell.fill = PatternFill(start_color='FF00FF00', end_color='FF00FF00', fill_type='solid')

    # Adjust column widths and add filters
    for col in range(1, len(fields) + 1):
        ws.column_dimensions[get_column_letter(col)].width = 30
    ws.auto_filter.ref = ws.dimensions

    wb.save(output_file)

def main():
    parser = argparse.ArgumentParser(description='Process Prowler scan results.')
    parser.add_argument('-s', '--severity', type=str, default='chml',
                        help='Severity levels to include: c (Critical), h (High), m (Medium), l (Low). Default: chml')
    args = parser.parse_args()

    severity_map = {'c': 'CRITICAL', 'h': 'HIGH', 'm': 'MEDIUM', 'l': 'LOW'}
    severity_filter = [s.upper() for s in args.severity if s.lower() in severity_map]

    if not severity_filter:
        print("No valid severity levels selected. Please include at least one severity level (c, h, m, l).")
        return

    input_directory = 'input_scans'
    output_directory = 'output'
    
    # Ensure output directory exists
    os.makedirs(output_directory, exist_ok=True)
    
    # Get all JSON files in the input directory
    input_files = [os.path.join(input_directory, f) for f in os.listdir(input_directory) if f.endswith('.json')]
    
    if not input_files:
        print("No JSON files found in the input directory.")
        return
    
    compiled_data = process_prowler_scans(input_files, severity_filter)
    
    # Save JSON output
    json_output = os.path.join(output_directory, 'compiled_unique_findings.json')
    with open(json_output, 'w') as file:
        json.dump(compiled_data, file, indent=2)
    
    # Save Excel output
    excel_output = os.path.join(output_directory, 'compiled_unique_findings.xlsx')
    save_excel_file(compiled_data, excel_output)
    
    print(f"Processing complete. {len(compiled_data)} findings saved in the '{output_directory}' directory.")
    print(f"Severity levels included: {', '.join([severity_map[s.lower()] for s in args.severity if s.lower() in severity_map])}")

if __name__ == "__main__":
    main()

```

   - Save the file (File > Save or Ctrl+S).

5. **Prepare Input Files**
   - Upload your Prowler scan JSON files to the `input_scans` directory.
   - You can do this by dragging and dropping files into the `input_scans` folder in the Cloud9 file browser, or by using AWS CLI commands in the terminal.

## Part 3: Running the Prowler Scan Processor

1. **Navigate to the Prowler Processor Directory**
   - In the terminal, ensure you're in the correct directory:
     ```
     cd ~/environment/prowler_processor
     ```

2. **Run the Script**
   - Execute the script with the desired severity levels:
     ```
     python prowler_processor.py -s chml
     ```
   - This will process all JSON files in the `input_scans` directory and include findings of Critical, High, Medium, and Low severity.
   - You can adjust the severity levels as needed (e.g., `python prowler_processor.py -s ch` for only Critical and High).

3. **Retrieve the Results**
   - After the script completes, you'll find two new files in the `output` directory:
     - `compiled_unique_findings.json`: A JSON file containing the compiled findings.
     - `compiled_unique_findings.xlsx`: An Excel file with the formatted findings.
   - You can download these files from the Cloud9 file browser (right-click > Download) or use AWS CLI commands to copy them to an S3 bucket for easier access.

## Part 4: Cleaning Up

When you're done using the Prowler Scan Processor:

1. **Stop the Cloud9 Environment**
   - In the Cloud9 service console, you can stop your environment to save costs when not in use.

2. **Delete the CloudFormation Stack (Optional)**
   - If you no longer need the environment, you can delete the CloudFormation stack to remove all created resources.
   - Go to the CloudFormation console, select your stack, and click "Delete".

## Troubleshooting

- If you encounter any "Permission denied" errors, you may need to make the script executable:
  ```
  chmod +x prowler_processor.py
  ```
- If you see any module import errors, make sure you've installed all required packages (`pip install openpyxl`).
- If the script runs but doesn't produce output, check that your input JSON files are in the correct format and contain findings.

Remember to handle your AWS credentials securely and follow AWS best practices for security when working with sensitive data.

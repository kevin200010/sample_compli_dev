import re


def extract_aws_cli_commands(response_message):
    """
    Extracts all AWS CLI commands from the response message using regex.
    Also removes any triple backticks (```) from the commands.
    """
    pattern = r"aws\s[a-zA-Z0-9-]+\s[^\n\r]*"  # Regex pattern to match AWS CLI commands
    commands = re.findall(pattern, response_message)

    # Remove triple backticks from each command
    cleaned_commands = [command.replace("```", "").strip() for command in commands]

    return cleaned_commands


def extract_aws_cli_command(response_message):
    pattern = r"aws\s[a-zA-Z0-9-]+\s[^\n\r]*"  # Regex pattern to match AWS CLI commands

    match = re.search(pattern, response_message)
    if match:
        return match.group().strip()
    else:
        return None

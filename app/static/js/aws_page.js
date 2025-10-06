document.addEventListener('DOMContentLoaded', (event) => {
    document.querySelectorAll('.print-json-button').forEach(button => {
        button.addEventListener('click', (e) => {
            const findingJson = JSON.parse(e.target.getAttribute('data-finding'));

            // Show loader
            document.querySelector('.loader-container').style.display = 'flex';

            // Send finding to the server
            fetch('/gpt_result', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ finding_json: findingJson })
            })
            .then(response => response.json())
            .then(data => {
                console.log('Success:', data);
                const updatedFinding = data.updated_finding;
                const awsCliCommands = data.aws_cli_commands;

                // Show updated finding in the modal
                document.getElementById('jsonContent').innerHTML = updatedFinding;
                const gptResultModal = new bootstrap.Modal(document.getElementById('gptResultModal'));
                gptResultModal.show();

                // Update "View AWS CLI Commands" button to handle commands
                const viewCommandsBtn = document.getElementById('viewCommandsBtn');
                viewCommandsBtn.onclick = () => {
                    // Populate the second modal with AWS CLI commands
                    const commandsModalContent = document.getElementById('commandsModalContent');
                    commandsModalContent.innerHTML = '';  // Clear previous content

                    awsCliCommands.forEach(command => {
                        const commandContainer = document.createElement('div');
                        commandContainer.classList.add('command-container');

                        const input = document.createElement('input');
                        input.setAttribute('type', 'text');
                        input.setAttribute('value', command);
                        input.classList.add('input');

                        const executeButton = document.createElement('button');
                        executeButton.setAttribute('type', 'button');
                        executeButton.classList.add('button');
                        executeButton.textContent = 'Execute';
                        executeButton.addEventListener('click', () => {
                            // Get the command from the input field
                            const commandValue = input.value.trim();

                            // Call the Flask route with the command value
                            fetch('/execute_command', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({ command: commandValue })
                            })
                            .then(response => response.json())
                            .then(data => {
                                console.log('Command executed:', data);
                                // Handle response if needed
                            })
                            .catch(error => {
                                console.error('Error executing command:', error);
                                // Handle error if needed
                            });
                        });

                        commandContainer.appendChild(input);
                        commandContainer.appendChild(executeButton);

                        commandsModalContent.appendChild(commandContainer);
                    });

                    // Show the commands modal
                    const commandsModal = new bootstrap.Modal(document.getElementById('commandsModal'));
                    commandsModal.show();
                };

                // Hide loader
                document.querySelector('.loader-container').style.display = 'none';
            })
            .catch((error) => {
                console.error('Error:', error);
                // Hide loader in case of error
                document.querySelector('.loader-container').style.display = 'none';
            });
        });
    });
});
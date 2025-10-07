(function () {
    document.addEventListener('DOMContentLoaded', function () {
        const openBtn = document.getElementById('openNovaSonicModal');
        const modalEl = document.getElementById('novaSonicModal');
        if (!modalEl) {
            return;
        }

        const submitBtn = document.getElementById('novaSonicSubmitBtn');
        const recordBtn = document.getElementById('novaSonicRecordBtn');
        const stopBtn = document.getElementById('novaSonicStopBtn');
        const inputEl = document.getElementById('novaSonicInput');
        const statusEl = document.getElementById('novaSonicStatus');
        const responseEl = document.getElementById('novaSonicResponse');
        const transcriptionEl = document.getElementById('novaSonicTranscription');
        const recordingHintEl = document.getElementById('novaSonicRecordingHint');

        let novaModal = null;
        if (typeof bootstrap !== 'undefined') {
            novaModal = new bootstrap.Modal(modalEl);
        }

        let mediaRecorder = null;
        let audioChunks = [];
        let audioBase64 = null;

        function updateStatus(message, type = 'info', show = true) {
            if (!statusEl) {
                return;
            }
            if (!show || !message) {
                statusEl.classList.add('d-none');
                statusEl.textContent = '';
                return;
            }
            statusEl.classList.remove('d-none');
            statusEl.className = `alert alert-${type}`;
            statusEl.textContent = message;
        }

        function resetRecordingState() {
            if (mediaRecorder && mediaRecorder.state !== 'inactive') {
                mediaRecorder.stop();
            }
            if (mediaRecorder && mediaRecorder.stream) {
                mediaRecorder.stream.getTracks().forEach((track) => track.stop());
            }
            mediaRecorder = null;
            audioChunks = [];
            audioBase64 = null;
            if (recordBtn) {
                recordBtn.disabled = false;
            }
            if (stopBtn) {
                stopBtn.disabled = true;
            }
            if (recordingHintEl) {
                recordingHintEl.textContent = '';
            }
        }

        function resetModal() {
            if (inputEl) {
                inputEl.value = '';
            }
            if (responseEl) {
                responseEl.innerHTML = '';
            }
            if (transcriptionEl) {
                transcriptionEl.textContent = '';
            }
            updateStatus('', 'info', false);
            resetRecordingState();
        }

        function setBusy(isBusy) {
            if (submitBtn) {
                submitBtn.disabled = isBusy;
            }
            if (recordBtn && (!mediaRecorder || mediaRecorder.state !== 'recording')) {
                recordBtn.disabled = isBusy;
            }
            if (stopBtn) {
                stopBtn.disabled = isBusy || !mediaRecorder || mediaRecorder.state !== 'recording';
            }
        }

        function convertBlobToBase64(blob) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onloadend = function () {
                    if (typeof reader.result === 'string') {
                        const [, encoded] = reader.result.split(',');
                        resolve(encoded || reader.result);
                    } else {
                        reject(new Error('Unable to process audio blob'));
                    }
                };
                reader.onerror = () => reject(new Error('Failed to read audio blob'));
                reader.readAsDataURL(blob);
            });
        }

        openBtn?.addEventListener('click', () => {
            resetModal();
            novaModal?.show();
        });

        modalEl.addEventListener('hidden.bs.modal', () => {
            resetModal();
        });

        recordBtn?.addEventListener('click', async () => {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                updateStatus('Microphone access is not supported in this browser.', 'danger');
                return;
            }

            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                mediaRecorder = new MediaRecorder(stream);
            } catch (error) {
                updateStatus('Microphone permission denied or unavailable.', 'danger');
                return;
            }

            audioChunks = [];
            audioBase64 = null;
            if (transcriptionEl) {
                transcriptionEl.textContent = '';
            }
            updateStatus('Recording… speak now.', 'info');
            if (recordingHintEl) {
                recordingHintEl.textContent = 'Recording in progress…';
            }
            if (recordBtn) {
                recordBtn.disabled = true;
            }
            if (stopBtn) {
                stopBtn.disabled = false;
            }

            mediaRecorder.addEventListener('dataavailable', (event) => {
                if (event.data && event.data.size > 0) {
                    audioChunks.push(event.data);
                }
            });

            mediaRecorder.addEventListener('stop', async () => {
                try {
                    const blob = new Blob(audioChunks, { type: 'audio/webm' });
                    if (blob.size === 0) {
                        audioBase64 = null;
                        updateStatus('Recording was empty. Please try again.', 'warning');
                        return;
                    }
                    audioBase64 = await convertBlobToBase64(blob);
                    updateStatus('Recording captured. You can submit your request.', 'success');
                    if (recordingHintEl) {
                        recordingHintEl.textContent = 'Recording saved – you may re-record if needed.';
                    }
                } catch (error) {
                    audioBase64 = null;
                    updateStatus('Unable to process the recording. Please try again.', 'danger');
                } finally {
                    if (recordBtn) {
                        recordBtn.disabled = false;
                    }
                    if (stopBtn) {
                        stopBtn.disabled = true;
                    }
                }
            });

            mediaRecorder.start();
        });

        stopBtn?.addEventListener('click', () => {
            if (!mediaRecorder || mediaRecorder.state === 'inactive') {
                return;
            }
            mediaRecorder.stop();
            if (mediaRecorder.stream) {
                mediaRecorder.stream.getTracks().forEach((track) => track.stop());
            }
        });

        submitBtn?.addEventListener('click', async () => {
            const message = inputEl?.value.trim();
            if (!message && !audioBase64) {
                updateStatus('Provide a question or record audio before submitting.', 'warning');
                return;
            }

            setBusy(true);
            updateStatus('Nova-Sonic is analysing your account…', 'info');
            if (responseEl) {
                responseEl.innerHTML = '';
            }

            try {
                const payload = {};
                if (message) {
                    payload.message = message;
                }
                if (audioBase64) {
                    payload.audio = audioBase64;
                }

                const response = await fetch('/nova_sonic_agent', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(payload),
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || 'Nova-Sonic request failed.');
                }

                if (data.transcription && transcriptionEl) {
                    transcriptionEl.textContent = `Transcription: ${data.transcription}`;
                }

                if (data.html && responseEl) {
                    responseEl.innerHTML = data.html;
                } else if (data.message && responseEl) {
                    responseEl.textContent = data.message;
                }

                updateStatus('Nova-Sonic response ready.', 'success');
            } catch (error) {
                updateStatus(error.message || 'Unexpected error contacting Nova-Sonic.', 'danger');
            } finally {
                setBusy(false);
            }
        });
    });
})();


// This is a small websockets test

const send_button = document.getElementById('send');
//const login_button = document.getElementById('login');
//const logout_button = document.getElementById('logout');
const start_button = document.getElementById('start');
const stop_button = document.getElementById('stop');
const content_div = document.getElementById('content');

let audioContext = null;
let ws = null;
let bufferDepth = 0;

async function startStreaming() {
    if (ws) {
        return;
    }

    // Create an AudioContext
    audioContext = new AudioContext({
        sampleRate: 16000 // Hz
    });

    // These are from BaseAudioContext
    console.log('audioContext.sampleRate=' + audioContext.sampleRate);
    console.log('audioContext.state=' + audioContext.state);
    console.log('audioContext.currentTime=' + audioContext.currentTime);

    // These are from AudioContext
    console.log('audioContext.baseLatency=' + audioContext.baseLatency);
    console.log('audioContext.outputLatency=' + audioContext.outputLatency);
    console.log('audioContext.baseLatency=' + audioContext.baseLatency);

    audioContext.onstatechange = (event) => {
        console.log('audioContext state changed. New state=' + audioContext.state);
        if (audioContext.state == 'closed') {
            audioContext = null;
        }
    };

    // Load a processor from the specified URL
    await audioContext.audioWorklet.addModule('audio_processor.js');

    // Create a new AudioWorkledNode using the processor we loaded
    // above ('audio-processor')
    const audioNode = new AudioWorkletNode(audioContext, 'audio-processor', {
        // One output with sterero (two channels)
        numberOfInputs: 0,
        numberOfOutputs: 1,
        outputChannelCount: [ 2 ],

        // Custom options that I can use my self
        processorOptions: { option1: 42, option2: 'foo' }
    });
    console.log('audioNode.channelCount=' + audioNode.channelCount);
    console.log('audioNode.channelCountMode=' + audioNode.channelCountMode);
    console.log('audioNode.channelInterpretation=' + audioNode.channelInterpretation);
    console.log('audioNode.parameters=' + JSON.stringify(audioNode.parameters));
    audioNode.connect(audioContext.destination);

    // Receiver for events sent from within our AudioWorkletProcessor
    audioNode.port.onmessage = (event) => {
        if (event.data.bufferDepth != bufferDepth) {
            bufferDepth = event.data.bufferDepth;
            content_div.innerText = 'bufferDepth: ' + bufferDepth;
            ws.send('' + bufferDepth);
        }
    };

    // Setup the websocket 
    ws = new WebSocket('/ws');
    ws.binaryType = 'arraybuffer';

    var nextFrameNo = 0;

    ws.onopen = (event) => {
        console.log('WebSocket connection opened.');
        send_button.disabled = false;
    };

    // Process incoming messages
    ws.onmessage = (event) => {
        // Convert to Float32 lpcm, which is what AudioWorkletNode expects
        const int16Array = new Int16Array(event.data);
        let float32Array = new Float32Array(int16Array.length - 1);
        for (let i = 0; i < int16Array.length - 1; i++) {
            float32Array[i] = int16Array[i] / 32768.0;
        }

        nextFrameNo = (int16Array[512] + 1);

        // Send the audio data to the AudioWorkletNode
        audioNode.port.postMessage({ message: 'audioData', audioData: float32Array, nextFrameNo: nextFrameNo });

        // Alternative method
        //audioNode.port.postMessage([ event.data ], [ event.data ]);
    }

    ws.onclose = (event) => {
        console.log('WebSocket connection closed.');
        //audioContext.close();
        //start_button.disabled = false;
        //stop_button.disabled = true;
        //ws = null;
        send_button.disabled = true;
    };

    ws.onerror = (event) => {
        console.error('WebSocket error:', event);
    };
}

async function stopStreaming() {
    console.log('Stopping audio');
    if (audioContext) {
        await ws.close();
        ws = null;

        //audioNode.disconnect(audioContext.destination);
        //await audioContext.suspend();  // suspend generates close on chromium!
        await audioContext.close();
        //audioContext = null;
    }
}


// Button handling
content_div.innerText = '0ms';

send_button.addEventListener('click', function() {
    // Check if WebSocket is open before sending a message
    if (ws && ws.readyState === WebSocket.OPEN) {
        // Send a message through the WebSocket
        ws.send('Hello, Server!');
        console.log('Message sent to server');
    } else {
        console.log('WebSocket is not open. Cannot send message.');
    }
});

//login_button.addEventListener('click', function() {
//    console.log('Login button pressed');
//});

//logout_button.addEventListener('click', function() {
//    console.log('Logout button pressed');
//});

start_button.addEventListener('click', function() {
    console.log('Start button pressed');
    startStreaming();
    stop_button.disabled = false;
    start_button.disabled = true;
});

stop_button.addEventListener('click', function() {
    console.log('Stop button pressed');
    stopStreaming();
    start_button.disabled = false;
    stop_button.disabled = true;
    content_div.innerText = '0ms';
});
stop_button.disabled = true;
send_button.disabled = true;

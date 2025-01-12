// This is an audio processor that is loaded from another script
//
// See:
// * https://stackoverflow.com/questions/78374582/audio-playback-from-a-websockets-endpoint-on-the-web
// * https://medium.com/@selcuk.sert/playing-audio-using-web-audio-api-949558576646
// * https://developer.mozilla.org/en-US/docs/Web/API/Web_Audio_API/Basic_concepts_behind_Web_Audio_API
// * https://googlechromelabs.github.io/web-audio-samples/audio-worklet

const NUMBUFFERS = 16;

// We might have our audio buffer here in this scope as well.
// See: https://developer.mozilla.org/en-US/docs/Web/API/AudioWorkletGlobalScope

class AudioProcessor extends AudioWorkletProcessor {
    constructor(options) {
        super();
        console.log('AudioProcessor() constructor. options=' + JSON.stringify(options));
        console.log('sampleRate=' + sampleRate);
        console.log('currentFrame=' + currentFrame);
        //this.buffer = new Float32Array();
        //this.underrun_buffer = new Float32Array(512);
        //this.first_call = true;

        this.buffers = new Array(NUMBUFFERS + 1);
        for (let i = 0; i < this.buffers.length; i++) {
            this.buffers[i] = new Float32Array(512);
        }

        this.capacity = NUMBUFFERS + 1;
        this.writePtr = 0;
        this.readPtr = 0;
        this.endPtr = NUMBUFFERS;

        this.playPart = 0;

        this.startOk = false;

        this.nextFrameNo = 0;
        this.bufferDepth = 0;

        this.lastWritePtr = 0;
        this.lastReadPtr = 0;

        // Receive audio data from the main thread, and add it to the buffer
        this.port.onmessage = (event) => {
            //if (this.buffer.length == 0) console.log('onmessage: audioData.length = ' + event.data.audioData.length);
            //let newFetchedData = new Float32Array(this.buffer.length + event.data.audioData.length);
            //newFetchedData.set(this.buffer, 0);
            //newFetchedData.set(event.data.audioData, this.buffer.length);
            //this.buffer = newFetchedData;

            if (event.data.nextFrameNo != this.nextFrameNo) {
                console.log('Missing frame: incoming: ' + event.data.nextFrameNo + ', next: ' + this.nextFrameNo);
            }

            this.nextFrameNo = (event.data.nextFrameNo + 1);

            let writeAquired = false;
            let aquiredWritePtr = 0;
            let aquiredEndPtr = this.endPtr;

            if (this.writePtr >= this.readPtr) {
                // State 1, write lead read
                //
                // We can write up to, but not including, this.capacity
                if (this.writePtr + 1 < this.capacity) {
                    aquiredWritePtr = this.writePtr;
                    writeAquired = true;
                    aquiredEndPtr = this.capacity - 1;
                } else {
                    // The requested amount of items to write will not fit in the
                    // remainig of the buffer. Check if we can wrap around and find
                    // space in the beginning of the buffer. If not, the buffer is full
                    if (1 < this.readPtr) {
                        // Ok to write the data at the beginning of the buffer
                        aquiredWritePtr = 0;
                        writeAquired    = true;
                        aquiredEndPtr   = this.writePtr;
                    }
                }
            } else {
                // State 2, read lead write
                //
                // We can write upto, but not including, this.readPtr
                if (this.writePtr + 1 < this.readPtr) {
                    aquiredWritePtr = this.writePtr;
                    writeAquired    = true;

                    // In state 2 we do not touch the end pointer
                }
            }

            //console.log('aquiredWritePtr=' + aquiredWritePtr + ', readPtr=' + this.readPtr);

            if (writeAquired) {
                this.endPtr = aquiredEndPtr;

                writeAquired = false;

                // We can now write data to this.buffers[aquiredWritePtr]
                for (let i = 0; i < 512; i++) {
                    this.buffers[aquiredWritePtr][i] = event.data.audioData[i];
                }

                // Alternative method
                //const int16Array = new Int16Array(event.data[0]);
                //for (let i = 0; i < int16Array.length; i++) {
                //    this.buffers[aquiredWritePtr][i] = int16Array[i] / 32768.0;
                //}

                // If aquiredWritePtr was set to 0 above, this write
                // will change the buffer state from 1 to 2
                this.writePtr = aquiredWritePtr + 1;
                this.bufferDepth = this.bufferDepth + 1;
                //console.log('Successful write to pos ' + aquiredWritePtr + '. readPtr=' + this.readPtr + ', bufferDepth='+ this.bufferDepth);

                // Send status back to our Node
                this.port.postMessage({ bufferDepth: this.bufferDepth });

                if (this.lastReadPtr == this.readPtr) {
                    console.log('We wrote more than once for the same readPtr(' + this.readPtr + '). bufferDepth=' + this.bufferDepth);
                }
                this.lastReadPtr = this.readPtr;
            } else {
                // Buffer overflow
                console.log('Overrun: writePtr=' + this.writePtr + ', readPtr=' + this.readPtr + ', bufferDepth=' + this.bufferDepth);
            }
        };
    }

    // Take a chunk from the buffer and send it to the output to be played
    // Called every 8ms (128 samples @ 16kHz). Expects us to fill in our samples in the provided
    // outputs buffer. It is initilized to 0 which will play silence if we
    // don't do anything
    process(inputs, outputs, parameters) {
        if (this.startOk == false) {
            if (this.bufferDepth > NUMBUFFERS/2) {
                this.startOk = true;
            } else {
                return true;
            }

        }

        const output = outputs[0];
        const left_channel  = output[0];
        const right_channel = output[1];

        let aquiredReadLen = 0;
        let aquiredReadPtr = 0;

        // Calculate how many item that are available in the buffer.
        // The calculation is different depending on the buffer state.
        if (this.writePtr >= this.readPtr) {
            // State 1 (write leads read).
            //
            // We can read up to, but not including or beyond, this.writePtr.
            // If the buffer is empty, i.e. this.writePtr == this.readPtr, aquiredReadLen
            // will be zero and the function will return false.

            aquiredReadPtr = this.readPtr;
            aquiredReadLen = this.writePtr - this.readPtr;
        } else {
            // State 2 (read leads write).
            //
            // We can read up to, but not including or beond, this.endPtr

            if (this.readPtr < this.endPtr) {
                aquiredReadPtr = this.readPtr;
                aquiredReadLen = this.endPtr - this.readPtr;
            } else {
                // Wrap around
                aquiredReadPtr = 0;
                aquiredReadLen = this.writePtr;
            }
        }

        if (aquiredReadLen > 0) {
            aquiredReadLen = 0;

            // It is now ok to play audio from this.buffers[aquiredReadPtr]
            for (let i = 0; i < left_channel.length; i++) {
                left_channel[i]  = this.buffers[aquiredReadPtr][i + this.playPart];
                right_channel[i] = this.buffers[aquiredReadPtr][i + this.playPart];
            }

            this.playPart = this.playPart + 128;
            // Atomically commit the update for the read pointer. If
            // aquiredReadPtr was set to 0 in acquireRead (wrap around), this
            // store operation will change the buffer state from 2 to 1.
            if (this.playPart == 512) {
                this.playPart = 0;
                this.readPtr = aquiredReadPtr + 1;
                this.bufferDepth = this.bufferDepth - 1;
                //console.log('Successfull play from pos ' + aquiredReadPtr + '. writePtr=' + this.writePtr + ', bufferDepth=' + this.bufferDepth);

                if (this.lastWritePtr == this.writePtr) {
                    console.log('We read more than once for the same writePtr(' + this.writePtr + '). bufferDepth=' + this.bufferDepth);
                }
                this.lastWritePtr = this.writePtr;
            }
        } else {
            console.log('Underrun: writePtr=' + this.writePtr + ', aquiredReadPtr=' + aquiredReadPtr + ', bufferDepth=' + this.bufferDepth);
        }

        return true;
    }
}

registerProcessor('audio-processor', AudioProcessor);

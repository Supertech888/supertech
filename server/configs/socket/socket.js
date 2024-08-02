const { Server } = require('socket.io')


const setupSocket = (httpServer) => {

    const io = new Server(httpServer, {
        cors: {
            origin: 'http://localhost:8080', // Replace with your frontend URL
            methods: ['GET', 'POST'],
        },
    });

    io.on('connection', (socket) => {
        console.log('A user connected');

        // Emit a welcome message to the connected client
        socket.emit('hello', 'world');
        socket.on('telegramUpdate', (data) => {
            console.log("🚀  file: socket.js:19  data:", data)
            io.emit('updateFromTelegram', data);
        });

        // Listen for the "newCase" event emitted from the backend
        socket.on('newCase', () => {
            // Emit a custom event to notify the connected client about the new case
            socket.emit('caseCreated', 'A new case has been created!');
        });

        socket.on('disconnect', () => {
            console.log('User disconnected');
        });
    });

    return io;

}

module.exports = setupSocket
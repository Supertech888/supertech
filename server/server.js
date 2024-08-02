require('dotenv').config();
const express = require('express')
const cors = require('cors')
const morgan = require('morgan')
const bodyParser = require('body-parser')
const mongoose = require('mongoose');
const app = express();


const session = require('express-session')
const redis = require('redis')
const RedisStore = require('connect-redis').default

const http = require('http').createServer(app);

//router
const caseRouter = require('./routers/caseRoute')
const ReAndLogRouter = require('./routers/LoginAndRegister')
const userRouter = require('./routers/userRouter')
const LoginAuth = require('./routers/login')
const currentTime = require('./routers/time');
const editorRouter = require('./routers/editors');


const { swaggerSpec, swaggerUi } = require('./configs/swagger/swagger');

//cron
const cronStart = require('./services/cron');
const { cronSendCaseMorning, cronSendCaseEvening } = require('./services/cron_sendCase');

//socket
const setupSocket = require('./configs/socket/socket');





const port = process.env.PORT || 3000
const mongoAtlas = process.env.DATABASE

//Docker
const { MONGO_IP, MONGO_USER, MONGO_PASSWORD, MONGO_PORT, REDIS_URL, REDIS_PORT, SESSION_SECRET, } = require('./configs/mongo/configs');

databaseDocker = `mongodb://${MONGO_USER}:${MONGO_PASSWORD}@${MONGO_IP}:${MONGO_PORT}/?authSource=admin`;

// เชื่อมต่อ MongoDB
connectWithRetry = () => {
    mongoose.connect(mongoAtlas, {
        useNewUrlParser: true,
        useUnifiedTopology: false
    }).then(() => console.log('Connected! to mongoose successfully'))
        .catch((err) => { setTimeout(connectWithRetry, 5000), err })
}
connectWithRetry()


//Get Ip
const IP = require('ip');
const axios = require('axios');
const { connect } = require('http2');
const bot_telegram = require('./services/bot_telegrsm');

const API_KEY = 'a2526ee543b54eff953197387f67d99d';
const URL = 'https://ipgeolocation.abstractapi.com/v1/?api_key=' + API_KEY;

const sendAPIRequest = async (ipAddress) => {
    const apiResponse = await axios.get(URL + "&ip_address=" + ipAddress);
    return apiResponse.data;
}

app.get('/', async (req, res) => {
    res.send('<h1>Im the Flash!!!</h1>')

})

// const io = require('socket.io')(http, {
//     cors: {
//         origin: 'http://localhost:8080', // Replace with your frontend URL
//         methods: ['GET', 'POST'],
//     },
// });
// io.on('connection', (socket) => {
//     console.log('A user connected');

//     // Handle socket events here

//     socket.on('disconnect', () => {
//         console.log('User disconnected');
//     });
// });


//swagger
// //  เชื่อมต่อ socket
// io.on('connection', (socket) => {
//     console.log('A user connected');

//     socket.on('chat message', (message) => {
//       console.log('Received message:', message);
//       io.emit('chat message', message); // ส่งข้อมูล message ให้กับทุกคนที่เชื่อมต่อ
//     });

//     socket.on('disconnect', () => {
//       console.log('A user disconnected');
//     });
//   });

// //redis 
// const redisClient = redis.createClient({ url: `redis://${REDIS_URL}:${REDIS_PORT}` })
// redisClient.connect().catch(console.error)

// app.enable('trust proxy')
// app.use(session({
//   proxy: true,
//   store: new RedisStore({client: redisClient}),
//   secret: SESSION_SECRET,
//   resave: false,
//   saveUninitialized: true,
//   cookie: {
//       secure: false,
//       httpOnly: true,
//       maxAge:3000000      // in ms
//   }
// }))

//app.use(bodyParser.json({limit: "20mb"}))
app.use(express.json());
app.use(morgan('dev'));
app.use(cors());




app.use('/api', caseRouter)
app.use('/api', ReAndLogRouter)
app.use('/api', userRouter)
app.use('/api', LoginAuth)
app.use('/api', editorRouter)
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use('/img', express.static('uploads'));

//start cron
cronStart.start();
cronSendCaseMorning.start();
cronSendCaseEvening.start();
//start setupSocket
setupSocket(http);

bot_telegram();




http.listen(port, () => console.log(`Server is running MY port ${port} 🚀`));










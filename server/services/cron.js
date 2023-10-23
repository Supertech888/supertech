const https = require('https')
const cron = require('cron').CronJob;



const cronStart = new cron('*/14 * * * *', () => {


    console.log(`Restart server`);

    https.get(process.env.BACKEND_URL, (res) => {
        // console.log("🚀  file: cron.js:12  process.env.BACKEND_URL:", process.env.BACKEND_URL)
        // console.log("🚀  file: cron.js:12  res:", res.statusCode)
        if (res.statusCode === 200) {
            console.log(`Server restarted  every 14 minutes `);
        } else {
            console.error(`failed to restart with status code: ${res.statusCode}`);
        }
    }).on('error', (error) => {
        console.error(`Restart Error : ${error.message}`);
    })

})

module.exports = cronStart

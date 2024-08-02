const TelegramBot = require('node-telegram-bot-api');


const bot_telegram = () => {
    // ระบุ Token ที่ได้จากการสร้างบอทใน BotFather
const token = '6700000221:AAFxM4FjxfSAa29nsVLT6HuJT6asEghHgwk';

// ระบุ Chat ID ของแชทห้องที่ต้องการ
const chatId = -1002052424926;

// สร้างบอท
const bot = new TelegramBot(token, {polling: true});

// ตรวจสอบข้อความในแชท
bot.on('message', (msg) => {
  
  const chatId = msg.chat.id;
  const text = msg.text;
  
  console.log("🚀  file: bot_telegrsm.js:18  chatId:", chatId)
  // ตรวจสอบคำที่มีการพิมพ์
  if (text.toLowerCase() === 'แก้ไขแล้ว' || text.toLowerCase() === 'แก้ไข') {
    // ส่งข้อความตอบกลับ
    bot.sendMessage(chatId, 'ขอบคุณ');
  }
});
}

module.exports = bot_telegram;
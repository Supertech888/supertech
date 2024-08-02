const mongoose = require("mongoose");

const schemaCase = mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
    },
    username: {
        type: String,
    },
    filename: {
      type: String,
    },
    start: {
      type: Date,
    },
    end: {
      type: Date,
    },
    dayOff: {
      type: String,
    },
    allDay: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
); //ทำการจัดเก็บข้อมูลช่วงเวลาในการสร้างหรือแก้ไข

module.exports = EventsDayOff = mongoose.model("dayoff_events", schemaCase);

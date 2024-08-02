const Cases = require("../models/caseModel");
const Users = require("../models/register");

const fs = require('fs')
// let count = 0;
// exports.requestUser = async (req, res) => {
//   const {
//     reporter,
//     problemDetail,
//     problem,
//     detail,
//     campgame,
//     wallet,
//     recorder,
//   } = req.body;
//   try {
//     count++;
//     // หา caseId ที่ใหม่ที่สุดในฐานข้อมูล
//     const latestCase = await Cases.findOne({}, { caseId: 1 }).sort({
//       createdAt: -1,
//     });

//     // สร้าง caseId ใหม่โดยเพิ่มค่าลำดับต่อไปจาก caseId ที่ใหม่ที่สุด
//     const caseIdCounter = latestCase
//       ? parseInt(latestCase.caseId.substring(5)) + 1
//       : 1;
//     const caseId = `BGMC${caseIdCounter.toString().padStart(5, "0")}`;

//     // const cases = await Cases.create({ reporter, typeproblem, casedetail ,campgame ,team,editors });
//     // res.json(cases);
//     let cases = await Cases.findOne({});
//     cases = new Cases({
//       caseId,
//       reporter,
//       problem,
//       problemDetail,
//       detail,
//       campgame,
//       wallet,
//       recorder,
//     });
//     await cases.save();
//     res.send({ message: "ทำการบันทึกข้อมูลสำเร็จ!!!", cases });
//     // console.log(cases);
//   } catch (error) {
//     console.log(error);
//   }
// };

exports.findCase = async (req, res) => {
  const id = req.params.id;
  // console.log(req.params.id);
  try {
    const cases = await Cases.find({ _id: id }).exec();
    res.json(cases);
  } catch (error) {
    console.log(error);
  }
};

exports.allCase = async (req, res) => {
  try {

    const cases = await Cases.find({}).exec();
    res.json(cases);
  } catch (error) {
    console.log(error);
  }
};

exports.updateCase = async (req, res) => {
  try {
    // console.log(req.body);
  } catch (error) {
    console.log(error);
  }
};
exports.removeCase = async (req, res) => {
  const id = req.params.id;
  try {
    const cases = await Cases.findOneAndRemove({ _id: id }).exec();
    res.json({ message: "ทำการลบข้อมูลสำเร็จ" });
  } catch (error) { }
};


exports.changeStatus = async (req, res) => {
  // console.log(req.body);
  // console.log(req.params);


  try {
    const cases = await Cases.findOneAndUpdate(
      { _id: req.body.id },
      { $set: { status: req.body.status, closeCaseBy: req.body.closeCaseBy } },
      { new: true }
    );
    console.log("🚀  file: caseController.js:97  cases:", cases)
    res.send(cases);
  } catch (error) {
    res.status(400).send("SerVer is Error");
  }
};

// exports.changeStatus1 = async (req, res) => {
//   // console.log(req.body);
//   // console.log(req.params);

//   try {
//     const user = await Users.findOneAndUpdate
//   } catch (error) {
//     res.status(400).send("SerVer is Error");
//   }
// };

exports.updateDetail = async (req, res) => {

  try {
    const { id, detail } = req.body;
    const data = req.body;


    if (typeof req.file !== 'undefined') {
      data.file = req.file.filename;

      await fs.unlink('./uploads/' + data.fileOld, (err) => {
        if (err) {
          console.log(err);
        } else {
          console.log('delete');
        }
      })
    }

    let updateFields = {};

    if (detail !== undefined && detail !== '') {
      updateFields.detail = detail;
    }

    if (data.file !== undefined && data.file !== '') {
      updateFields.file = data.file;
    }

    const detailNew = await Cases.findOneAndUpdate(
      { _id: id },
      { $set: updateFields },
      { new: true }
    ).exec();

    res.json(detailNew);
  } catch (error) {
    console.error("Error updating detail:", error);
    res.status(400).json({ error: "Server error" });
  }
};



exports.updateCaseDetail = (req, res) => {
  console.log(req.body);
  console.log(req.params);
};



// const getDay = new Date().getDate()
// const getMonth = new Date().getMonth();
// const getYear = new Date().getFullYear();

// console.log(getYear, getMonth, getDay,);




// exports.requestUser = async (req, res) => {

//   const {
//     reporter,
//     problemDetail,
//     problem,
//     detail,
//     campgame,
//     wallet,
//     recorder,
//   } = req.body;

//   const latestCase = await Cases.findOne({}, { caseId: 1 }).sort({
//     createdAt: -1,
//   });

//   const caseIdCounter = latestCase
//     ? parseInt(latestCase.caseId.substring(5)) + 1
//     : 1;



//   // const currentDate = new Date();
//   // const formattedDate = currentDate.toISOString().substring(0, 10).replace(/-/g, '');


//   const caseId = `BGMC${caseIdCounter.toString().padStart(5, "0")}`;
//   // ตรวจสอบว่า caseId นี้มีอยู่ในฐานข้อมูลแล้วหรือไม่
//   const existingCase = await Cases.findOne({ caseId });

//   if (existingCase) {
//     // หากมี caseId นี้อยู่แล้ว ทำการจัดการข้อผิดพลาดที่นี่
//     res.status(409).send({ error: "caseId ซ้ำกัน" });
//   } else {
//     // หากไม่ซ้ำ ทำการบันทึกข้อมูล
//     const cases = new Cases({
//       caseId,
//       reporter,
//       problem,
//       problemDetail,
//       detail,
//       campgame,
//       wallet,
//       recorder,
//     });
//     await cases.save();
//     res.send({ message: "ทำการบันทึกข้อมูลสำเร็จ!!!", cases });
//   }


// };

// function สำหรับการ กำหนดเลขเคส

const generateCase = async () => {

  // หา caseId ที่ใหม่ที่สุดในฐานข้อมูล
  const latestCase = await Cases.findOne({}, { caseId: 1 }).sort({
    createdAt: -1,
  });

  // สร้าง caseId ใหม่โดยเพิ่มค่าลำดับต่อไปจาก caseId ที่ใหม่ที่สุด
  const caseIdCounter = latestCase
    ? parseInt(latestCase.caseId.substring(5)) + 1
    : 1;
  const caseId = `BGMC${caseIdCounter.toString().padStart(5, "0")}`;


  // ตรวจสอบว่าเลขเคสนี้มีอยู่ในฐานข้อมูลหรือไม่ ถ้ามีให้สร้างเลขเคสใหม่อีกครั้ง
  const existingCase = await Cases.findOne({ caseId });

  if (existingCase) {
    return generateCase();
  }

  return caseId;

}

const saveNewCase = async (caseData) => {

  const caseId = await generateCase();
  const newCase = new Cases({ ...caseData, caseId });
  await newCase.save();
  return newCase;

}

// ตัวอย่างการใช้งาน
exports.requestUser = async (req, res) => {


  const { reporter, problemDetail, problem, detail, campgame, wallet, recorder, editors } = req.body;

  const data = req.body
  console.log("🚀  file: caseController.js:241  data:", data)

  console.log('fff', req.file);
  try {
    if (req.file) {
      // data.file = {
      //   data: req.file.filename,
      //   contentType: req.file.mimetype
      // }
      data.file = req.file.filename


    }
    console.log("🚀  file: caseController.js:241  data:", data)

    const newCase = await saveNewCase(data);
    res.send({ message: 'ทำการบันทึกข้อมูลสำเร็จ!!!', cases: newCase });

  } catch (error) {
    console.log("🚀  file: caseController.js:263  error:", error)

    res.status(500).send({ message: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล', error });
  }
}


exports.updateMessageId = async (req, res) => {
  const { id, messageId } = req.body;
  console.log(req.body.messageId);

  try {
    const detailNew = await Cases.findOneAndUpdate(
      { _id: id },
      { $set: { messageId: { messageId: messageId } } },
      { new: true }
    ).exec();

    res.json(detailNew);
    console.log("🚀  file: caseController.js:297  detailNew:", detailNew)

  } catch (error) {
    console.error("Error updating messageId:", error);
    res.status(400).send("Server error");
  }


}
exports.deletePicture = async (req, res) => {
  console.log("🚀  file: caseController.js:319  req:", req.body.file)

  const id = req.params.id
  const file = req.body.file

  await Cases.findOneAndUpdate(
    { _id: id, file: { $exists: true } },
    { $set: { file: "" } },
    { new: true }
  ).exec()

  if (file) {
    await fs.unlink('./uploads/' + file, (err) => {
      err ? console.log('delete fail') : res.status(200).send({ message: "Delate Success" })
    })

  }

}
//แบบที่สอง
// exports.deletePicture = async (req, res) => {
//   console.log("🚀  file: caseController.js:319  req:", req.params.id)
//   const id = req.params.id

//   const result = await Cases.findOne({ _id: id }).exec();
//   if (result?.file) {
//     await fs.unlink('./uploads/' + result.file, (err) => {
//       err ? console.log('delete fail') : console.log('delete success')
//     })

//   }
//   console.log("🚀  file: caseController.js:329  res:", result)

//   const updatedResult = await Cases.findOneAndUpdate(
//     { _id: id, file: { $exists: true } },
//     { $unset: { file: "" } },
//     { new: true }
//   ).exec();

//   res.json(updatedResult);

// }
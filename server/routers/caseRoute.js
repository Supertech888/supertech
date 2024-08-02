const express = require('express');
const { requestUser, allCase, updateCase, removeCase, findCase, changeStatus, updateDetail, updateCaseDetail,updateMessageId ,deletePicture} = require('../controllers/caseController');
const { createDetailCase, allDetailCase, createDetailCase2, allDetailCase2, typeData, getTypeData,deleteTypeData } = require('../controllers/detailCaseForm');
const { upload } = require('../middleware/uploadFile');
const { authen } = require('../middleware/auth');



const router = express.Router();



//สร้าง case 

router.post('/createcase',upload, requestUser)

//เรียกดูเคสทั้งหมด


router.get('/listcase',allCase)



// เรียกดูเคส 1 เคส

router.get('/findcase/:id', findCase)



// update case
/**
 * @swagger
 *  /change-status{id}:
 *   put:
 *     tags: [Cases]
 *     summary: Retrieve a list of JSONPlaceholder users
 *     description: Retrieve a list of users from JSONPlaceholder. Can be used to populate a list of fake users when prototyping or testing an API.
*/
router.put('/change-status/:id', updateCase)

router.put('/change-detail/:id',upload, updateDetail)

router.delete('/deletePicture/:id',deletePicture)

router.post('/change-status', changeStatus)





router.post('/updateMessageId', updateMessageId)
// delete case
/**
 * @swagger
 *  /delete/{id}:
 *   delete:
 *     tags: [Cases]
 *     summary: Retrieve a list of JSONPlaceholder users
 *     description: Retrieve a list of users from JSONPlaceholder. Can be used to populate a list of fake users when prototyping or testing an API.
*/
router.delete('/delete/:id', removeCase)

// router.put('/changdetail/:id' , updateDetail)
router.put('/update-detail/:id', updateCaseDetail)


router.post('/create-detailcase', createDetailCase2)


router.post('/detail-case', createDetailCase2)

router.post('/detail-type', typeData)
router.get('/get-type', getTypeData)
router.delete('/delete-type/:id', deleteTypeData)



router.get('/listdetail', allDetailCase)

router.get('/listdetail2', allDetailCase2)


module.exports = router;
const multer = require("multer");
const path = require("path");

const destination = path.resolve("temp");

const storage = multer.diskStorage({
    destination,
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
})

const limits = {
    fileSize: 1024 * 1024
}


const upload = multer({
    storage,
    limits,
})

module.exports = upload;
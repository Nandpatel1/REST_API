import { Product } from '../models';
import multer from 'multer';
import path from 'path';
import CustomErrorHandler from '../services/CustomErrorHandler';
import fs from 'fs';
import Joi from 'joi';
import productSchema from '../validators/productValidator';

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
})

const handleMultipartData = multer({ storage, limits: { fileSize: 1000000 * 5 } }).single('image'); //limit: 5mb (1mb = 1e6 Bytes)

const productController = {
    async store(req, res, next) {
        // multipart form data
        handleMultipartData(req, res, async (err) => {
            if (err) {
                return next(CustomErrorHandler.serverError(err.message));
            }
            const filePath = req.file.path;

            // Validation
            const { error } = productSchema.validate(req.body);

            if (error) {
                // delete the uploaded file (path: rootFolder/uploads/filename.png)
                fs.unlink(`${appRoot}/${filePath}`, (err) => {
                    if (err) {
                        return next(CustomErrorHandler.serverError(err.message));
                    }
                });
                return next(error);
            }

            const { name, price, size } = req.body;
            let document;
            try {
                document = await Product.create({
                    name,
                    price,
                    size,
                    image: filePath
                })
            } catch (err) {
                return next(err);
            }
            res.status(201).json(document);
        });
    },

    update(req, res, next) {
        handleMultipartData(req, res, async (err) => {
            if (err) {
                return next(CustomErrorHandler.serverError(err.message));
            }
            let filePath;
            if (req.file) {
                filePath = req.file.path;
            }

            // Validation
            const { error } = productSchema.validate(req.body);

            if (error) {
                // delete the uploaded file (path: rootFolder/uploads/filename.png)
                if (req.file) {
                    fs.unlink(`${appRoot}/${filePath}`, (err) => {
                        if (err) {
                            return next(CustomErrorHandler.serverError(err.message));
                        }
                    });
                }
                return next(error);
            }

            const { name, price, size } = req.body;
            let document;
            try {
                document = await Product.findOneAndUpdate({ _id: req.params.id }, {
                    name,
                    price,
                    size,
                    ...(req.file && { image: filePath })
                }, { new: true });
            } catch (err) {
                return next(err);
            }
            res.status(201).json(document);
        });
    },

    async destroy(req, res, next) {
        const document = await Product.findOneAndRemove({ _id: req.params.id });
        if (!document) {
            return next(new Error('Nothing to delete'));
        }

        // delete image
        const imagePath = document._doc.image; // use _doc to access image without getter
        // const imagePath = document.image;
        fs.unlink(`${appRoot}/${imagePath}`, (err) => {
            if (err) {
                return next(CustomErrorHandler.serverError());
            }
            return res.json(document);
        });
    },

    async index(req, res, next) {
        let documents;
        // pagination library: mongoose-pagination (If there are lots of products then use pagination)
        try {
            documents = await Product.find().select('-updatedAt -__v');
        }
        catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.json(documents);
    },

    async show(req, res, next) {
        let document;
        try {
            document = await Product.findOne({ _id: req.params.id }).select('-updatedAt -__v');
        }
        catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.json(document);
    },

    async cartItems(req, res, next) {
        let documents;
        try {
            documents = await Product.find({ _id: { $in: req.body.ids } }).select('-updatedAt -__v');
        }
        catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.json(documents);
    }
}

export default productController;

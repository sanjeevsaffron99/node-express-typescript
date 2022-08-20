import * as Koa from 'koa';
import { OtpConcern } from './models';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import MessageService from '../../services/messageService';

export const verifyUserOtp = async (otp: any, user: any, concern: any) => {
    const otpDoc = await OtpConcern.findOneAndDelete({
        concern,
        otp,
        uniqueId: user
    });
    return otpDoc;
};

export const verifyOTP =
    (model: any, concern: string) => async (ctx: Koa.Context) => {
        const { user, otp } = ctx.request.body;
        const otpDoc = await verifyUserOtp(otp, user, concern);

        if (!otpDoc) {
            ctx.throw(401, 'Invalid OTP');
        }
        await model.findByIdAndUpdate(user, {
            $set: {
                'authentication.otpVerified': true
            }
        });
        ctx.body = {
            response: 'OTP verified successfully',
            status: 1
        };
    };

export const sendOtpToUser = async (
    mobile: any,
    user: any,
    concern: any,
    message: string = null
) => {
    const otp = Math.floor(1000 + Math.random() * 9000);
    const validTill = new Date();
    validTill.setMinutes(validTill.getMinutes() + 2);
    const otpDoc = await OtpConcern.findOneAndUpdate(
        {
            concern,
            uniqueId: user
        },
        {
            concern,
            otp,
            uniqueId: user,
            validTill
        },
        {
            upsert: true,
            new: true
        }
    );

    let MSG;
    if (message) {
        MSG = message.replace('#OTP#', `${otp}`);
    } else {
        MSG = `${otp} is your OTP for Nipige registration. OTP is valid for only 2 mins`;
    }

    const sms = new MessageService();
    sms.sendSms({
        mobile,
        concern,
        message: MSG
    }).then();
};

export const sendOtpToUserV2 = async (
    mobile: any,
    user: any,
    concern: any,
    tenant: any,
    email?: any,
    channel?: any
) => {
    let otp = Math.floor(1000 + Math.random() * 9000);
    const validTill = new Date();
    validTill.setMinutes(validTill.getMinutes() + 5);
    const existing = await OtpConcern.findOne({ concern, uniqueId: user });
    if (existing === null) {
        OtpConcern.findOneAndUpdate(
            { concern, uniqueId: user },
            { concern, otp, uniqueId: user, validTill },
            { upsert: true, new: true }
        ).exec();
    } else {
        otp = existing.otp;
    }
    const messageService = new MessageService();
    if (channel === 'EMAIL' && email) {
        messageService
            .sendEmail({
                to: email,
                concern,
                tenant,
                data: {
                    otp
                }
            })
            .then()
            .catch();
    } else {
        messageService
            .sendSms({
                mobile,
                concern,
                tenant,
                data: {
                    otp
                }
            })
            .then()
            .catch();
    }
    return;
};

export const genOTP =
    (model: any, concern: string) => async (ctx: Koa.Context) => {
        const { user } = ctx.request.body;
        const userDoc = await model.findById(user, {
            'authentication.phone': 1
        });
        if (!userDoc) {
            ctx.throw(401, 'No such user exists');
        }

        await sendOtpToUser(userDoc.authentication.phone, user, concern);

        ctx.body = {
            response: 'otp send successfully',
            status: 1
        };
    };

export const createLoggedInPayload = async (
    doc: any,
    tenantId: any,
    authorization: boolean
) => {
    const jwtPayload = {
        _id: (doc as any)._id,
        category: (doc as any).category,
        tenant: tenantId,
        officeHierarchy: (doc as any).officeHierarchy,
        phone: (doc as any).authentication.phone,
        roles: (doc as any).authorization ? doc.authorization.roles : [],
        authentication: (doc as any).authentication
    };

    if (doc.customerNo) {
        Object.assign(jwtPayload, { customerNo: doc.customerNo });
    }
    if (doc.businessNo) {
        Object.assign(jwtPayload, { businessNo: doc.businessNo });
    }

    if (doc.preferences && doc.preferences.modeOfSale) {
        Object.assign(jwtPayload, {
            preferences: { modeOfSale: doc.preferences.modeOfSale }
        });
    }

    let permissions;
    if (authorization) {
        permissions = [];
        // permissions = await RolePermission.find({
        //     role: {
        //         $in: jwtPayload.roles
        //     }
        // }).populate('permission');
    }

    const token = await jwt.sign(jwtPayload, process.env.JWT_SECRET, {
        expiresIn: '365 days'
    });

    return {
        user: doc,
        token,
        permissions
    };
};

export const login = (model: any, options: any) => async (ctx: Koa.Context) => {
    const tenant = ctx.tenant;
    const { userName, email, phone, password, deviceId, deviceType } =
        ctx.request.body;
    const { authorization, passwordCb, deviceValidation } = options;
    const { modelName } = model;
    const loginConcern = userName
        ? ['userName', userName]
        : email
        ? ['email', email]
        : ['phone', phone];
    const condition = {
        [`authentication.${loginConcern[0]}`]: loginConcern[1]
    };

    // if (modelName === 'Customer' && tenant) {
    //     Object.assign(condition, { tenant: tenant });
    // } else if (modelName === 'Customer' && !tenant) {
    //     ctx.throw(401, 'Tenant not found or not active');
    // }

    /**
     * If we have tenant id make sure to check tenant id
     * login which require tenant id need to have
     * [assureTenant, login] as handler
     */

    Object.assign(condition, { isDeleted: { $ne: true } });

    Object.assign(condition, {
        status: { $nin: ['INACTIVE', 'PENDING', 'CANCELLED'] }
    });

    if (tenant) {
        Object.assign(condition, { tenant: tenant });
    }

    const doc = deviceValidation
        ? await model.findOne(condition).populate('tenant')
        : await model.findOne(condition);
    if (!doc) {
        ctx.throw(401, 'No such user exists!!');
    }

    const currentTime = new Date().getTime();
    if (doc.authentication.lockUntil > currentTime) {
        const timeToUnlock =
            (doc.authentication.lockUntil - currentTime) / 60 / 1000;
        ctx.throw(
            401,
            `Too many failed attempts, try logging again in ${Math.ceil(
                timeToUnlock
            )} minutes`
        );
    }

    function availableDeviceId(devices: any, deviceId: any) {
        /*
        check if device is available in list
        */
        return devices.find((i: any) => i.deviceId == deviceId) ? true : false;
    }

    if (deviceValidation && deviceType != 'WEB') {
        if (
            doc.tenant &&
            doc.tenant.preferences.deviceBinding.deviceBindingEnabled
        ) {
            if (!deviceId && !deviceType) {
                ctx.throw(401, `'deviceId' and 'deviceType' required`);
            }

            if (
                deviceType != doc.preferences.offlineSaleType &&
                doc.preferences.offlineSaleType != 'NA'
            ) {
                ctx.throw(401, `invalid device type`);
            }

            const deviceIds = doc.authentication.deviceDetails;
            const availableDevice = availableDeviceId(deviceIds, deviceId);

            console.log(availableDevice);

            if (
                deviceIds.length <
                    doc.tenant.preferences.deviceBinding.maxAllowedDevices &&
                !availableDevice
            ) {
                /*
                no. of devices < maxAllowedDevices and deviceId not available in existing list
                 */
                doc.authentication.deviceDetails.push({ deviceId: deviceId });
                await doc.save();
            } else if (
                deviceIds.length >=
                    doc.tenant.preferences.deviceBinding.maxAllowedDevices &&
                !availableDevice
            ) {
                /*
                Exceeded max device limit
                 */
                ctx.throw(401, `Exceeded max connected devices`);
            }
            // will continue when binding
        }
    }

    if (doc.tenant && doc.tenant.preferences) {
        doc.tenant = doc.tenant._id;
    }

    const passwordHash = passwordCb
        ? passwordCb(doc)
        : doc.authentication.passwordHash;
    const valid = await bcrypt.compare(password, passwordHash);
    if (!valid) {
        doc.authentication.loginAttempts += 1;
        if (doc.authentication.loginAttempts >= 3) {
            const date = new Date();
            doc.authentication.lockUntil = date.setMinutes(
                date.getMinutes() + 5
            );
        }
        doc.save();
        ctx.throw(401, 'Invalid password!!');
    }

    doc.authentication.loginAttempts = 0;
    doc.authentication.lockUntil = null;
    await doc.save();

    let tenantId: any = null;
    if (modelName === 'Tenant') {
        tenantId = (doc as any)._id;
    } else if ((doc as any).category !== 'NA') {
        tenantId = (doc as any).tenant;
    }

    const resPayload = await createLoggedInPayload(
        doc,
        tenantId,
        authorization
    );

    ctx.body = {
        response: resPayload,
        status: 1
    };
};

export const signJWT = async (payload, expire) => {
    const token = await jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: expire
    });
    return token;
};

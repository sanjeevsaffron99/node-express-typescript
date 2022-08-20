export const loginWithOtp = async (ctx: Koa.Context) => {
    const { mobile, otp, referralCode, state, city, referralCustomerNo } =
        ctx.request.body;

    let userData: any = await Customer.findOne({
        tenant: ctx.tenant,
        'authentication.phone': mobile
    });

    if (!userData) {
        try {
            const uniqueId = crypto.randomBytes(20).toString('hex');
            const customerRole = await getDefaultRoleByCategory('Customer');
            const password = crypto.randomBytes(48).toString('hex');
            const payload: any = {
                name: {
                    first: 'New',
                    last: 'User'
                },
                authentication: {
                    phone: mobile,
                    userName: uniqueId,
                    email: `${uniqueId}@trigital.in`,
                    securityQuestions: {
                        question: 'what is your first school',
                        answer: crypto.randomBytes(18).toString('hex')
                    }
                },
                category: 'Customer',
                tenant: ctx.tenant
            };
            payload.authorization = { roles: [] };
            payload.authorization.roles = [customerRole._id];
            payload.authentication.passwordHash = bcrypt.hashSync(password);
            payload.authentication.forceChangePass = true;

            let referralId = '';
            if (referralCode) {
                referralId = referralCode;
            } else if (referralCustomerNo) {
                const customerSearch = await Customer.findOne({
                    customerNo: referralCustomerNo
                });
                if (customerSearch === null) {
                    ctx.throw('Refferal code is not exist.');
                }
                if (customerSearch) {
                    referralId = customerSearch._id;
                }
            }
            if (referralId) {
                payload.metaInfo = {
                    refererId: referralId,
                    firstLogin: true
                };
            }
            Object.assign(payload, { deviceInfo: {} });
            if (ctx.request.ip) {
                payload.deviceInfo.ip = ctx.request.ip;
            }
            const counterDoc = await Counter.findOneAndUpdate(
                { tenant: ctx.tenant },
                { $inc: { customerNo: 1 } },
                { new: true }
            );
            const { customerNo, customerSeries } = counterDoc;
            payload.customerNo =
                customerSeries +
                String(customerNo).padStart(8 - customerSeries.length, '0');
            userData = await Customer.create(payload);
            const userLoginToken = await createLoggedInPayload(
                userData,
                userData.tenant,
                true
            );
        } catch (error) {
            console.log(error);

            const errData = {
                user: { phone: mobile },
                tenant: ctx.tenant,
                requestBody: JSON.stringify(ctx.request.body),
                response: JSON.stringify(error),
                type: 'OTP_REGISTRATION'
            };
            ActivityLog.create(errData).then();
        }
        // await createWallet(userLoginToken.token);
        // await sendTransfer(userData._id, ctx.tenant, 20, true);
    }

    if (!otp) {
        await sendOtpToUserV2(
            mobile,
            userData._id,
            customerOtpConcern,
            userData.tenant
        );
        ctx.body = {
            status: 1,
            message: 'OTP has been sent to your registered mobile number.'
        };
        return;
    }

    const verified = await verifyUserOtp(otp, userData._id, customerOtpConcern);

    if (!verified) {
        ctx.throw(401, 'Invalid OTP');
    }
    if (userData.authentication.otpVerified === false) {
        Customer.findByIdAndUpdate(userData._id, {
            $set: {
                'authentication.otpVerified': true
            }
        }).then();
        userData.authentication.otpVerified = true;
        events.emit('registration', userData, '');
    }

    if (userData?.metaInfo?.firstLogin) {
        if (userData?.metaInfo?.refererId) {
            try {
                await sendWalletBonus(
                    ctx.tenant,
                    userData?.metaInfo?.refererId,
                    state,
                    city,
                    userData._id.toString()
                );
            } catch (e) {
                console.log(
                    `Error transferring reward balance, errMsg: ${e.message}`
                );
            }
        }
        await sendWalletBonus(
            ctx.tenant,
            userData._id.toString(),
            state,
            city,
            false
        );
        Customer.findByIdAndUpdate(userData._id, {
            $set: {
                'metaInfo.firstLogin': false
            }
        }).then();
    }

    const authToken = await createLoggedInPayload(
        userData,
        userData.tenant,
        true
    );

    ctx.body = {
        status: 1,
        response: authToken
    };
};
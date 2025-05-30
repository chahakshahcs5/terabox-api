import { FormData, Client, buildConnector, request } from 'undici';
import { Cookie, CookieJar } from 'tough-cookie';
import { filesize } from 'filesize';

import child_process from 'node:child_process';
import crypto from 'node:crypto';
import tls from 'node:tls';

function makeRemoteFPath(sdir, sfile){
    const tdir = sdir.match(/\/$/) ? sdir : sdir + '/';
    return tdir + sfile;
}

class FormUrlEncoded {
    constructor(params) {
        this.data = new URLSearchParams();
        if(typeof params === 'object' && params !== null){
            for (const [key, value] of params.entries()) {
                this.data.append(key, value);
            }
        }
    }
    set(param, value){
        this.data.set(param, value);
    }
    append(param, value){
        this.data.append(param, value);
    }
    delete(param){
        this.data.delete(param);
    }
    str(){
        return this.data.toString().replace(/\+/g, '%20');
    }
}

function signDownload(s1, s2) {
    const p = new Uint8Array(256);
    const a = new Uint8Array(256);
    const result = [];
    
    Array.from({ length: 256 }, (_, i) => {
        a[i] = s1.charCodeAt(i % s1.length);
        p[i] = i;
    });
    
    let j = 0;
    Array.from({ length: 256 }, (_, i) => {
        j = (j + p[i] + a[i]) % 256;
        [p[i], p[j]] = [p[j], p[i]]; // swap
    });
    
    let i = 0; j = 0;
    Array.from({ length: s2.length }, (_, q) => {
        i = (i + 1) % 256;
        j = (j + p[i]) % 256;
        [p[i], p[j]] = [p[j], p[i]]; // swap
        const k = p[(p[i] + p[j]) % 256];
        result.push(s2.charCodeAt(q) ^ k);
    });
    
    return Buffer.from(result).toString('base64');
}

function checkMd5val(md5){
    if(typeof md5 !== 'string') return false;
    return /^[a-f0-9]{32}$/.test(md5);
}

function checkMd5arr(arr) {
    if (!Array.isArray(arr)) return false;
    return arr.every(item => {
        return checkMd5val(item);
    });
}

function decryptMd5(md5) {
    if (md5.length !== 32) return md5;
    
    const restoredHexChar = (md5.charCodeAt(9) - 'g'.charCodeAt(0)).toString(16);
    const o = md5.slice(0, 9) + restoredHexChar + md5.slice(10);
    
    let n = '';
    for (let i = 0; i < o.length; i++) {
        const orig = parseInt(o[i], 16) ^ (i & 15);
        n += orig.toString(16);
    }
    
    const e =
        n.slice(8, 16) + // original e[0..7]
        n.slice(0, 8) +  // original e[8..15]
        n.slice(24, 32) + // original e[16..23]
        n.slice(16, 24);  // original e[24..31]
    
    return e;
}

function changeBase64Type(str, mode = 1){
    return mode === 1
        ? str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '%3D')  // to url-safe
        : str.replace(/-/g,  '+').replace(/_/g,  '/').replace(/%3D/g, '='); // to url-unsafe
}

function aesDecrypt(pp1, pp2) {
    pp1 = changeBase64Type(pp1, 2);
    pp2 = changeBase64Type(pp2, 2);
    
    const cipherText = pp1.substring(16);
    const key = Buffer.from(pp2, 'utf8');
    const iv = Buffer.from(pp1.substring(0, 16), 'utf8');
    
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    
    let decrypted = decipher.update(cipherText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

function md5LenPad(str) {
    if (!str) return str;
    const len = str.length;
    return len < 10 ? str + '0' + len : str + len;
}

/**
 * RSA-шифрование строки с публичным ключом (в PEM-формате)
 * @param {string} message - исходное сообщение
 * @param {string} publicKeyPEM - публичный RSA ключ в PEM формате
 * @param {number} mode - если 2 → md5 + md5LenPad, иначе напрямую
 * @returns {string} base64-строка с зашифрованными данными
 */
function encryptRSA(message, publicKeyPEM, mode = 1) {
    if (mode === 2) {
        const md5 = crypto.createHash('md5').update(message).digest('hex');
        message = md5LenPad(md5);
    }
    
    const buffer = Buffer.from(message, 'utf8');
    
    const encrypted = crypto.publicEncrypt({
            key: publicKeyPEM,
            padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        buffer,
    );
    
    return encrypted.toString('base64');
)

class TeraBoxApp {
    FormUrlEncoded = FormUrlEncoded;
    SignDownload = signDownload;
    CheckMd5Val = checkMd5val;
    CheckMd5Arr = checkMd5arr;
    DecryptMd5 = decryptMd5;
    TERABOX_TIMEOUT = 10000;
    
    data = {
        csrf: '',
        logid: '0',
        pcftoken: '',
        bdstoken: '',
        jsToken: '',
        pubkey: '',
    };
    params = {
        whost: 'https://www.terabox.com',
        uhost: 'https://c-jp.terabox.com',
        lang: 'en',
        app: {
            app_id: 250528,
            web: 1,
            channel: 'dubox',
            clienttype: 0, // 5 is wap?
        },
        ver_android: '3.40.0',
        ua: 'terabox;1.37.0.7;PC;PC-Windows;10.0.22631;WindowsTeraBox',
        cookie: '',
        auth: {},
        account_name: '',
        is_vip: true,
        vip_type: 2,
        space_used: 0,
        space_total: 2 * Math.pow(1024, 3),
        space_available: 2 * Math.pow(1024, 3),
        cursor: 'null',
    };
    
    constructor(authData, authType = 'ndus') {
        this.params.cookie = `lang=${this.params.lang}`;
        if(authType == 'ndus'){
            this.params.cookie += authData ? '; ndus=' + authData : '';
        }
        else{
            throw new Error('initTBApp', { cause: 'AuthType Not Supported!' });
        }
    }
    
    async updateAppData(customPath){
        const url = new URL(this.params.whost + (customPath ? `/${customPath}` : '/main'));
        
        try{
            const req = await request(url, {
                headers:{
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT * 2),
            });
            
            if(req.headers['set-cookie']){
                const cJar = new CookieJar();
                this.params.cookie.split(';').map(cookie => cJar.setCookieSync(cookie, this.params.whost));
                if(typeof req.headers['set-cookie'] == 'string'){
                    req.headers['set-cookie'] = [req.headers['set-cookie']];
                }
                for(const cookie of req.headers['set-cookie']){
                    cJar.setCookieSync(cookie.split('; ')[0], this.params.whost);
                }
                this.params.cookie = cJar.getCookiesSync(this.params.whost).map(cookie => cookie.cookieString()).join('; ');
            }
            
            const rdata = await req.body.text();
            const tdataRegex = /<script>var templateData = (.*);<\/script>/;
            const jsTokenRegex = /window.jsToken%20%3D%20a%7D%3Bfn%28%22(.*)%22%29/;
            const tdata = rdata.match(tdataRegex) ? JSON.parse(rdata.match(tdataRegex)[1]) : {};
            
            if(tdata.jsToken){
                tdata.jsToken = tdata.jsToken.match(/%28%22(.*)%22%29/)[1];
            }
            else if(rdata.match(jsTokenRegex)){
                tdata.jsToken = rdata.match(jsTokenRegex)[1];
            }
            else{
                const isLoginReq = req.headers.location == '/login' ? true : false;
                console.error('[ERROR] Failed to update jsToken', (isLoginReq ? '[Login Required]' : ''));
            }
            
            if(req.headers.logid){
                this.data.logid = req.headers.logid;
            }
            
            this.data.csrf = tdata.csrf || '';
            this.data.pcftoken = tdata.pcftoken || '';
            this.data.bdstoken = tdata.bdstoken || '';
            this.data.jsToken = tdata.jsToken || '';
            
            return tdata;
        }
        catch(error){
            const errorPrefix = '[ERROR] Failed to update jsToken:';
            if(error.name == 'TimeoutError'){
                console.error(errorPrefix, error.message);
                return;
            }
            error = new Error('updateAppData', { cause: error });
            console.error(errorPrefix, error);
        }
    }
    
    async doReq(req_url, req_options = {}, retries = 4){
        const url = new URL(this.params.whost + req_url);
        let reqm_options = structuredClone(req_options);
        let req_headers = {};
        
        if(reqm_options.headers){
            req_headers = reqm_options.headers;
            delete reqm_options.headers;
        }
        
        const save_cookies = reqm_options.save_cookies;
        delete reqm_options.save_cookies;
        const silent_retry = reqm_options.silent_retry;
        delete reqm_options.silent_retry;
        const req_timeout = reqm_options.timeout ? reqm_options.timeout : this.TERABOX_TIMEOUT;
        delete reqm_options.timeout;
        
        try {
            const options = {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    ...req_headers,
                },
                ...reqm_options,
                signal: AbortSignal.timeout(req_timeout),
            };
            
            const req = await request(url, options);
            
            if(save_cookies && req.headers['set-cookie']){
                const cJar = new CookieJar();
                this.params.cookie.split(';').map(cookie => cJar.setCookieSync(cookie, this.params.whost));
                if(typeof req.headers['set-cookie'] == 'string'){
                    req.headers['set-cookie'] = [req.headers['set-cookie']];
                }
                for(const cookie of req.headers['set-cookie']){
                   cJar.setCookieSync(cookie.split('; ')[0], this.params.whost);
                }
                this.params.cookie = cJar.getCookiesSync(this.params.whost).map(cookie => cookie.cookieString()).join('; ');
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch(error){
            if (retries > 0) {
                await new Promise(resolve => setTimeout(resolve, 500));
                if(!silent_retry){
                    console.error('[ERROR] DoReq:', req_url, '|', error.code, ':', error.message, '(retrying...)');
                }
                return await this.doReq(req_url, req_options, retries - 1);
            }
            throw new Error('doReq', { cause: error });
        }
    }
    
    async checkLogin(){
        const url = new URL(this.params.whost + '/api/check/login');
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch(error){
            throw new Error('checkLogin', { cause: error });
        }
    }
    
    async getAccountData(){
        const url = new URL(this.params.whost + '/rest/2.0/membership/proxy/user');
        url.search = new URLSearchParams({
            method: 'query',
        });
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.error_code == 0){
                this.params.vip_type = rdata.data.member_info.is_vip;
                this.params.is_vip = this.params.vip_type > 0 ? true : false;
            }
            return rdata;
        }
        catch(error){
            throw new Error('getAccountData', { cause: error });
        }
    }
    
    async getPassport(){
        const url = new URL(this.params.whost + '/passport/get_info');
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.errno == 0){
                this.params.account_name = rdata.data.display_name;
            }
            return rdata;
        }
        catch (error) {
            throw new Error('getPassport', { cause: error });
        }
    }
    
    async getQuota(){
        const url = new URL(this.params.whost + '/api/quota');
        url.search = new URLSearchParams({
            checkexpire: 1,
            checkfree: 1,
        });
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.errno == 0){
                rdata.available = rdata.total - rdata.used;
                this.params.space_available = rdata.available;
                this.params.space_total = rdata.total;
                this.params.space_used = rdata.used;
            }
            return rdata;
        }
        catch (error) {
            throw new Error('getQuota', { cause: error });
        }
    }
    
    async getCoinsCount(){
        const url = new URL(this.params.whost + '/rest/1.0/inte/system/getrecord');
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getCoinsCount', { cause: error });
        }
    }
    
    async getRemoteDir(remoteDir, page = 1){
        const url = new URL(this.params.whost + '/api/list');
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
        });
        
        const formData = new FormUrlEncoded();
        formData.append('order', 'name');
        formData.append('desc', 0);
        formData.append('dir', remoteDir);
        formData.append('num', 20000);
        formData.append('page', page);
        formData.append('showempty', 0);
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getRemoteDir', { cause: error });
        }
    }
    
    async getRecycleBin(){
        const url = new URL(this.params.whost + '/api/recycle/list');
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
            order: 'name',
            desc: 0,
            num: 20000,
            page: 1,
        });
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getRecycleBin', { cause: error });
        }
    }
    
    async clearRecycleBin(){
        const url = new URL(this.params.whost + '/api/recycle/clear');
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
            // 'async': 1,
        });
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('clearRecycleBin', { cause: error });
        }
    }
    
    async getUserInfo(user_id){
        user_id = parseInt(user_id);
        const url = new URL(this.params.whost + '/api/user/getinfo');
        url.search = new URLSearchParams({
            user_list: JSON.stringify([user_id]),
            need_relation: 0,
            need_secret_info: 1,
        });
        
        try{
            if(isNaN(user_id) || user_id < 1){
                throw new Error(`${user_id} is not user id`);
            }
            
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getUserInfo', { cause: error });
        }
    }
    
    async precreateFile(data){
        const formData = new FormUrlEncoded();
        formData.append('path', makeRemoteFPath(data.remote_dir, data.file));
        // formData.append('target_path', data.remote_dir);
        formData.append('autoinit', 1);
        formData.append('size', data.size);
        formData.append('file_limit_switch_v34', 'true');
        formData.append('block_list', '[]');
        formData.append('rtype', 2);
        
        if(data.upload_id && typeof data.upload_id == 'string' && data.upload_id != ''){
            formData.append('uploadid', data.upload_id);
        }
        
        // check if has correct md5 values
        if(this.CheckMd5Val(data.hash.slice) && this.CheckMd5Val(data.hash.file)){
            formData.append('content-md5', data.hash.file);
            formData.append('slice-md5', data.hash.slice);
        }
        
        // check crc32int and ignore field for crc32 out of range
        if(Number.isSafeInteger(data.hash.crc32) && data.hash.crc32 >= 0 && data.hash.crc32 <= 0xFFFFFFFF){
            formData.append('content-crc32', data.hash.crc32);
        }
        
        // check chunks hash
        if(!this.CheckMd5Arr(data.hash.chunks)){
            const predefinedHash = ['5910a591dd8fc18c32a8f3df4fdc1761']
            
            if(data.size > 4 * 1024 * 1024){
                predefinedHash.push('a5fc157d78e6ad1c7e114b056c92821e');
            }
            
            formData.set('block_list', JSON.stringify(predefinedHash));
        }
        else{
            formData.set('block_list', JSON.stringify(data.hash.chunks));
        }
        
        // formData.append('local_ctime', '');
        // formData.append('local_mtime', '');
        
        const api_prefixurl = data.is_teratransfer ? 'a' : '';
        const url = new URL(this.params.whost + `/api/${api_prefixurl}precreate`);
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
        });
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('precreateFile', { cause: error });
        }
    }
    
    async rapidUpload(data){
        const formData = new FormUrlEncoded();
        formData.append('path', makeRemoteFPath(data.remote_dir, data.file));
        // formData.append('target_path', data.remote_dir);
        formData.append('content-length', data.size);
        formData.append('content-md5', data.hash.file);
        formData.append('slice-md5', data.hash.slice);
        formData.append('content-crc32', data.hash.crc32);
        // formData.append('local_ctime', '');
        // formData.append('local_mtime', '');
        formData.append('block_list', JSON.stringify(data.hash.chunks || []));
        formData.append('rtype', 2);
        formData.append('mode', 1);
        
        if(!this.CheckMd5Val(data.hash.slice) || !this.CheckMd5Val(data.hash.file)){
            const badMD5 = new Error('Bad MD5 Slice Hash or MD5 File Hash');
            throw new Error('rapidUpload', { cause: badMD5 });
        }
        
        if(!Number.isSafeInteger(data.hash.crc32) || data.hash.crc32 < 0 || data.hash.crc32 > 0xFFFFFFFF){
            formData.delete('content-crc32');
        }
        
        if(!Array.isArray(data.hash.chunks)){
            // use unsafe rapid upload if we don't have chunks hash
            formData.delete('block_list');
            formData.set('rtype', 3);
        }
        
        const url = new URL(this.params.whost + '/api/rapidupload');
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
        });
        
        try{
            if(data.size < 256 * 1024){
                throw new Error(`File size too small!`);
            }
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('rapidUpload', { cause: error });
        }
    }
    
    async getUploadHost(){
        const url = new URL(this.params.whost + '/rest/2.0/pcs/file?method=locateupload');
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            this.params.uhost = 'https://' + rdata.host;
            return rdata;
        }
        catch (error) {
            throw new Error('getUploadHost', { cause: error });
        }
    }
    
    async uploadChunk(data, partseq, blob, reqHandler, externalAbort) {
        const timeoutAborter = new AbortController;
        const timeoutId = setTimeout(() => { timeoutAborter.abort(); }, this.TERABOX_TIMEOUT);
        externalAbort = externalAbort ? externalAbort : new AbortController().signal;
        
        const url = new URL(`${this.params.uhost}/rest/2.0/pcs/superfile2`);
        url.search = new URLSearchParams({
            method: 'upload',
            ...this.params.app,
            // type: 'tmpfile',
            path: makeRemoteFPath(data.remote_dir, data.file),
            uploadid: data.upload_id,
            // uploadsign: 0,
            partseq: partseq,
        });
        
        if(data.is_teratransfer){
            url.searchParams.append('useteratransfer', '1')
        }
        
        const formData = new FormData();
        formData.append('file', blob, 'blob');
        
        const req = await request(url, {
            method: 'POST',
            body: formData,
            headers: {
                'User-Agent': this.params.ua,
                'Cookie': this.params.cookie,
            },
            signal: AbortSignal.any([
                externalAbort,
                timeoutAborter.signal,
            ]),
        });
        
        clearTimeout(timeoutId);
        
        if (req.statusCode !== 200) {
            throw new Error(`HTTP error! Status: ${req.statusCode}`);
        }
        
        const res = await req.body.json();
        
        if (res.error_code) {
            const uploadError = new Error(`Upload failed! Error Code #${res.error_code}`);
            uploadError.data = res;
            throw uploadError;
        }
        
        return res;
    }
    
    async createDir(remoteDir){
        const formData = new FormUrlEncoded();
        formData.append('path', remoteDir);
        formData.append('isdir', 1);
        formData.append('block_list', '[]');
        
        const url = new URL(this.params.whost + '/api/create');
        url.search = new URLSearchParams({
            a: 'commit',
            ...this.params.app,
            jsToken: this.data.jsToken,
        });
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('createFolder', { cause: error });
        }
    }
    
    async createFile(data) {
        const formData = new FormUrlEncoded();
        formData.append('path', makeRemoteFPath(data.remote_dir, data.file));
        // formData.append('isdir', 0);
        formData.append('size', data.size);
        formData.append('isdir', 0);
        
        // check if has correct md5 values
        if(this.CheckMd5Val(data.hash.slice) && this.CheckMd5Val(data.hash.file)){
            formData.append('content-md5', data.hash.file);
            formData.append('slice-md5', data.hash.slice);
        }
        
        // check crc32int and ignore field for crc32 out of range
        if(Number.isSafeInteger(data.hash.crc32) && data.hash.crc32 >= 0 && data.hash.crc32 <= 0xFFFFFFFF){
            formData.append('content-crc32', data.hash.crc32);
        }
        
        formData.append('block_list', JSON.stringify(data.hash.chunks));;
        formData.append('uploadid', data.upload_id);
        formData.append('rtype', 2);
        
        // formData.append('local_ctime', '');
        // formData.append('local_mtime', '');
        // formData.append('zip_quality', '');
        // formData.append('zip_sign', '');
        // formData.append('is_revision', 0);
        // formData.append('mode', 2); // 2 is Batch Upload
        // formData.append('exif_info', exifJsonStr);
        
        const api_prefixurl = data.is_teratransfer ? 'anno' : '';
        const url = new URL(this.params.whost + `/api/${api_prefixurl}create`);
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
        });
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.md5){
                // encrypted etag
                rdata.emd5 = rdata.md5;
                // decrypted etag (without chunk count)
                rdata.md5 = this.DecryptMd5(rdata.emd5);
                // set custom etag
                rdata.etag = rdata.md5;
                if(data.hash.chunks.length > 1){
                    rdata.etag += '-' + data.hash.chunks.length;
                }
            }
            
            return rdata;
        }
        catch (error) {
            console.log(error);
            throw new Error('createFile', { cause: error });
        }
    }
    
    async filemanager(operation, fmparams){
        const url = new URL(this.params.whost + '/api/filemanager');
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
            // 'async': 2,
            onnest: 'fail',
            opera: operation, // delete, copy, move, rename
        });
        
        if(!Array.isArray(fmparams)){
            throw new Error('filemanager', { cause: new Error('FS paths should be in array!') });
        }
        
        // For Delete: ["/path1","path2.rar"]
        // For Move: [{"path":"/myfolder/source.bin","dest":"/target/","newname":"newfilename.bin"}]
        // For Copy same as move
        // + "ondup": newcopy, overwrite (optional, skip by default)
        // For rename [{"id":1111,"path":"/dir1/src.bin","newname":"myfile2.bin"}]
        
        // operation - copy (file copy), move (file movement), rename (file renaming), and delete (file deletion)
        // opera=copy: filelist: [{"path":"/hello/test.mp4","dest":"","newname":"test.mp4"}]
        // opera=move: filelist: [{"path":"/test.mp4","dest":"/test_dir","newname":"test.mp4"}]
        // opera=rename: filelist：[{"path":"/hello/test.mp4","newname":"test_one.mp4"}]
        // opera=delete: filelist: ["/test.mp4"]
        
        const formData = new FormUrlEncoded();
        formData.append('filelist', JSON.stringify(fmparams));
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('filemanager', { cause: error });
        }
    }
    
    async shortUrlInfo(shareId){
        const url = new URL(this.params.whost + '/api/shorturlinfo');
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
            shorturl: 1 + shareId,
            root: 1,
        });
        
        try{
            const connector = buildConnector({ ciphers: tls.DEFAULT_CIPHERS + ':!ECDHE-RSA-AES128-SHA' });
            const client = new Client(this.params.whost, { connect: connector });
            const req = await request(url, {
                method: 'GET',
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                dispatcher: client,
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('shortUrlInfo', { cause: error });
        }
    }
    
    async shortUrlList(shareId, remoteDir, page = 1){
        remoteDir = remoteDir || ''
        const url = new URL(this.params.whost + '/share/list');
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
            shorturl: shareId,
            by: 'name',
            order: 'asc',
            num: 20000,
            dir: remoteDir,
            page: page,
        });
        
        if(remoteDir == ''){
            url.searchParams.append('root', '1');
        }
        
        try{
            const connector = buildConnector({ ciphers: tls.DEFAULT_CIPHERS + ':!ECDHE-RSA-AES128-SHA' });
            const client = new Client(this.params.whost, { connect: connector });
            const req = await request(url, {
                method: 'GET',
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                dispatcher: client,
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('shortUrlList', { cause: error });
        }
    }
    
    async fileDiff(){
        const formData = new FormUrlEncoded();
        formData.append('cursor', this.params.cursor);
        if(this.params.cursor == 'null'){
            formData.append('c', 'full');
        }
        formData.append('action', 'manual');
        
        const url = new URL(this.params.whost + '/api/filediff');
        url.search = new URLSearchParams({
            ...this.params.app,
            block_list: 1,
            // rand: '',
            // time: '',
            // vip: this.params.vip_type,
            // wp_retry_num: 2,
            // lang: this.params.lang,
            // logid: '',
        });
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.errno == 0){
                this.params.cursor = rdata.cursor;
                if(!Array.isArray(rdata.request_id)){
                    rdata.request_id = [ rdata.request_id ];
                }
                if(rdata.has_more){
                    // Extra FileDiff request...
                    const rFileDiff = await this.fileDiff();
                    if(rFileDiff.errno == 0){
                        rdata.reset = rFileDiff.reset;
                        rdata.request_id = rdata.request_id.concat(rFileDiff.request_id);
                        rdata.entries = Object.assign({}, rdata.entries, rFileDiff.entries);
                        rdata.has_more = rFileDiff.has_more;
                    }
                }
            }
            return rdata;
        }
        catch (error) {
            this.params.cursor = 'null';
            throw new Error('fileDiff', { cause: error });
        }
    }
    
    async genPanToken(){
        const url = new URL(this.params.whost + '/api/pantoken');
        url.search = new URLSearchParams({
            ...this.params.app,
            lang: this.params.lang,
            u: 'https://www.terabox.com',
        });
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('genPanToken', { cause: error });
        }
    }
    
    async getHomeInfo(){
        const url = new URL(this.params.whost + '/api/home/info');
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
        });
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            
            if(rdata.errno == 0){
                rdata.data.signb = this.SignDownload(rdata.data.sign1, rdata.data.sign3);
            }
            
            return rdata;
        }
        catch (error) {
            throw new Error('getHomeInfo', { cause: error });
        }
    }
    
    async download(fs_ids, signb){
        const url = new URL(this.params.whost + '/api/download');
        
        const formData = new FormUrlEncoded();
        for(const [k, v] of this.params.app.entries()){
             formData.append(k, v);
        }
        formData.append('jsToken', this.data.jsToken);
        formData.append('fidlist', JSON.stringify(fs_ids));
        formData.append('type', 'dlink');
        formData.append('vip', 2); // this.params.vip_type
        formData.append('sign', signb); // base64 sign from getHomeInfo
        formData.append('timestamp', Math.round(Date.now()/1000));
        formData.append('need_speed', '1'); // Premium speed?..
        formData.append('bdstoken', this.data.bdstoken);
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            
            return rdata;
        }
        catch (error) {
            throw new Error('download', { cause: error });
        }
    }
    
    async getFileMeta(remote_file_list){
        const url = new URL(this.params.whost + '/api/filemetas');
        
        const formData = new FormUrlEncoded();
        formData.append('dlink', 1);
        formData.append('origin', 'dlna');
        formData.append('target', JSON.stringify(remote_file_list));
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            
            return rdata;
        }
        catch (error) {
            throw new Error('getFileMeta', { cause: error });
        }
    }
    
    async getRecentUploads(page = 1){
        const url = new URL(this.params.whost + '/rest/recent/listall');
        url.search = new URLSearchParams({
            ...this.params.app,
            version:  this.params.ver_android,
            // num: 20000, ???
            // page: page, ???
        });
        
        try{
            const req = await request(url, {
                method: 'GET',
                body: formData.str(),
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            
            return rdata;
        }
        catch (error) {
            throw new Error('getRecentUploads', { cause: error });
        }
    }
    
    async getPublicKey(){
        const url = new URL(this.params.whost + '/passport/getpubkey');
        try{
            const req = await request(url, {
                method: 'GET',
                headers: {
                    'User-Agent': this.params.ua,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            
            if(rdata.code == 0){
                this.data.pubkey = aesDecrypt(rdata.data.pp1, rdata.data.pp2);
            }
            
            return rdata;
        }
        catch (error) {
            throw new Error('getPublicKey', { cause: error });
        }
    }
}

export default TeraBoxApp;

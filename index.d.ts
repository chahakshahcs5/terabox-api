// index.d.ts

declare module "@chahakshah/terabox-api" {
  export interface FormUrlEncodedParams {
    [key: string]: string;
  }

  export class FormUrlEncoded {
    constructor(params?: FormUrlEncodedParams);
    set(param: string, value: string): void;
    append(param: string, value: string): void;
    delete(param: string): void;
    str(): string;
    url(): URLSearchParams;
  }

  export function signDownload(s1: string, s2: string): string;
  export function checkMd5val(md5: any): boolean;
  export function checkMd5arr(arr: any): boolean;
  export function decodeMd5(md5: string): string;
  export function changeBase64Type(str: string, mode?: 1 | 2): string;
  export function decryptAES(pp1: string, pp2: string): string;
  export function encryptRSA(
    message: string,
    publicKeyPEM: string | Buffer,
    mode?: 1 | 2
  ): string;
  export function prandGen(
    seval: string,
    encpwd: string,
    email: string,
    random: string,
    browserid?: string,
    client?: string
  ): string;

  export interface TeraBoxAppData {
    csrf: string;
    logid: string;
    pcftoken: string;
    bdstoken: string;
    jsToken: string;
    pubkey: string;
  }

  export interface TeraBoxAppParams {
    whost: string;
    uhost: string;
    lang: string;
    app: {
      app_id: number;
      web: number;
      channel: string;
      clienttype: number;
    };
    ver_android: string;
    ua: string;
    cookie: string;
    auth: Record<string, unknown>;
    account_id: number;
    account_name: string;
    is_vip: boolean;
    vip_type: number;
    space_used: number;
    space_total: number;
    space_available: number;
    cursor: string;
  }

  export interface FileHashData {
    crc32: number;
    slice: string;
    file: string;
    etag: string;
    chunks: string[];
  }

  export interface UploadData {
    remote_dir: string;
    file: string;
    size: number;
    upload_id?: string;
    hash: FileHashData;
    uploaded?: boolean[];
    hash_check?: boolean;
  }

  export interface ProgressData {
    all: number;
    start: number;
    parts: Record<number, number>;
    maxTries?: number;
  }

  export interface PassportInfo {
    code: number;
    data: PassportInfoData;
    logid: number;
    msg: string;
  }
  export interface PassportInfoData {
    display_name: string;
    head_url: string;
    region_domain_prefix: string;
    url_domain_prefix: string;
  }

  export interface UserMembership {
    data: UserMembershipData;
    error_code: number;
    error_msg: string;
    request_id: string;
  }
  export interface UserMembershipData {
    cur_country: CurCountry;
    member_info: MemberInfo;
    pay_center_version: number;
    privilege_infos: any[];
    reg_country: RegCountry;
    reminder: Reminder;
  }

  export interface CurCountry {
    name: string;
    speed_show_ratio: number;
    support_vip: number;
    upload_speed_ratio: number;
  }

  export interface MemberInfo {
    can_cancel_renew: number;
    can_trial: number;
    has_iap_record: boolean;
    is_auto_renew: number;
    is_vip: number;
    is_vip_level: number;
    platform: number;
    price_currency: string;
    raw_price: number;
    renew_price: number;
    renew_time: number;
    show_grace_tips: number;
    vip_end_time: number;
    vip_end_time_without_grace: number;
    vip_left_time: number;
  }

  export interface RegCountry {
    name: string;
    speed_show_ratio: number;
    support_vip: number;
    upload_speed_ratio: number;
  }

  export interface Reminder {
    vip_expire_time: number;
  }

  export interface AccountQuota {
    errmsg: string;
    errno: number;
    expire: boolean;
    free: number;
    newno: string;
    request_id: number;
    sbox_used: number;
    server_time: number;
    total: number;
    used: number;
    available: number;
  }

  export interface CoinsCount {
    errno: number;
    errmsg: string;
    data: CoinsCountData;
    logid: string;
  }

  export interface CoinsCountData {
    can_used_cnt: number;
    will_expire_cnt: number;
  }

  export interface PassportPreLogin {
    code: number;
    data: PassportPreLoginData;
    logid: number;
    msg: string;
  }

  export interface PassportPreLoginData {
    random: number;
    seval: string;
    timestamp: number;
  }

  export interface PassportLogin {
    code: number;
    data: PassportLoginData;
    logid: number;
    msg: string;
  }

  export interface PassportLoginData {
    cur_country: string,
    displayName: string,
    headUrl: string,
    need_protect: number,
    reg_country: string,
    reg_time: number,
    region_domain_prefix: string,
    url_domain_prefix: string,
    ndus: string
  }

  export interface PassportLoginError {
    request_id: number;
    code: number;
    errmsg: string;
  }

  export interface RemoteDirectory {
    errno: number;
    guid_info: string;
    list: RemoteDirectoryList[];
    request_id: number;
    guid: number;
  }
  export interface RemoteDirectoryList {
    tkbind_id: number;
    server_filename: string;
    category: number;
    unlist: number;
    isdir: number;
    dir_empty?: number;
    play_forbid: number;
    wpfile: number;
    local_mtime: number;
    share: number;
    pl: number;
    local_ctime: number;
    empty?: number;
    real_category: string;
    extent_int2: number;
    server_ctime: number;
    extent_tinyint7: number;
    extent_tinyint9: number;
    size: number;
    fs_id: number;
    owner_type: number;
    path: string;
    owner_id: number;
    from_type: number;
    server_atime: number;
    server_mtime: number;
    oper_id: number;
    thumbs?: RemoteDirectoryThumbs;
    lodocpreview?: string;
    docpreview?: string;
    md5?: string;
  }

  export interface RemoteDirectoryThumbs {
    url3: string;
    url2: string;
    url1: string;
  }

  export interface CheckLogin {
    errno: number;
    newno: string;
    request_id: number;
    show_msg: string;
    uk: number;
  }

  export interface FileMeta {
    errno: number;
    info: FileMetaInfo[];
    request_id: number;
  }

  export interface FileMetaInfo {
    extent_tinyint4: number;
    extent_tinyint1: number;
    category: number;
    fs_id: number;
    ifhassubdir?: number;
    videotag: number;
    oper_id: number;
    play_forbid: number;
    wpfile: number;
    local_mtime: number;
    share: number;
    extent_tinyint3: number;
    errno: number;
    local_ctime: number;
    extent_tinyint5: number;
    owner_type: number;
    privacy: number;
    real_category: string;
    path_md5: number;
    server_ctime: number;
    extent_tinyint9: number;
    upload_type: number;
    size: number;
    tkbind_id: number;
    isdir: number;
    extent_int3: number;
    path: string;
    owner_id: number;
    from_type: number;
    extent_tinyint2: number;
    server_filename: string;
    server_mtime: number;
    dlink?: string;
    thumbs?: FileMetaInfoThumbs;
    docpreview?: string;
    lodocpreview?: string;
    md5?: string;
    file_key?: string;
  }

  export interface FileMetaInfoThumbs {
    icon: string;
    url3: string; // Large
    url2: string; // Medium
    url1: string; // Small
  }

  export interface FileManager {
    errno: number;
    info: any[];
    request_id: number;
    taskid: number;
  }

  export interface PrecreateFile {
    block_list: number[];
    errmsg: string;
    errno: number;
    newno: string;
    path: string;
    request_id: number;
    return_type: number;
    server_time: number;
    uploadid: string;
  }

  export interface CreateFile {
    category: number;
    ctime: number;
    errmsg: string;
    errno: number;
    from_type: number;
    fs_id: number;
    isdir: number;
    md5: string;
    mtime: number;
    name: string;
    newno: string;
    path: string;
    request_id: number;
    server_filename: string;
    server_time: number;
    size: number;
    emd5: string;
    etag: string;
  }

  class TeraBoxApp {
    TERABOX_DOMAIN: string;
    TERABOX_TIMEOUT: number;
    data: TeraBoxAppData;
    params: TeraBoxAppParams;

    FormUrlEncoded: typeof FormUrlEncoded;
    SignDownload: typeof signDownload;
    CheckMd5Val: typeof checkMd5val;
    CheckMd5Arr: typeof checkMd5arr;
    DecodeMd5: typeof decodeMd5;
    ChangeBase64Type: typeof changeBase64Type;
    DecryptAES: typeof decryptAES;
    EncryptRSA: typeof encryptRSA;
    PRandGen: typeof prandGen;

    constructor(authData: string, authType?: string);

    updateAppData(customPath?: string, retries?: number): Promise<any>;
    setVipDefaults(): void;
    doReq(req_url: string, req_options?: any, retries?: number): Promise<any>;
    getSysCfg(): Promise<any>;
    checkLogin(): Promise<CheckLogin>;
    passportPreLogin(email: string): Promise<PassportPreLogin>;
    passportLogin(preLoginData: any, email: string, pass: string): Promise<any>;
    regSendCode(email: string): Promise<any>;
    regVerify(regToken: string, code: string | number): Promise<any>;
    regFinish(regToken: string, pass: string): Promise<any>;
    passportGetInfo(): Promise<PassportInfo>;
    userMembership(): Promise<UserMembership>;
    getCurrentUserInfo(): Promise<any>;
    getUserInfo(user_id: number | string): Promise<any>;
    getQuota(): Promise<AccountQuota>;
    getCoinsCount(): Promise<any>;
    getRemoteDir(remoteDir: string, page?: number): Promise<RemoteDirectory>;
    getRecycleBin(page?: number): Promise<any>;
    clearRecycleBin(): Promise<any>;
    precreateFile(data: UploadData): Promise<PrecreateFile>;
    rapidUpload(data: UploadData): Promise<any>;
    remoteUpload(urls: string, remote_dir?: string): Promise<any>;
    getUploadHost(): Promise<any>;
    uploadChunk(
      data: UploadData,
      partseq: number,
      blob: Blob | Buffer,
      reqHandler?: Function,
      externalAbort?: AbortSignal
    ): Promise<any>;
    createDir(remoteDir: string): Promise<any>;
    createFile(data: UploadData): Promise<CreateFile>;
    filemanager(operation: string, fmparams: any[]): Promise<FileManager>;
    shareList(page?: number): Promise<any>;
    shareSet(filelist: string[], pass?: string, period?: number): Promise<any>;
    shareCancel(shareid_list?: number[]): Promise<any>;
    shortUrlInfo(shortUrl: string): Promise<any>;
    shortUrlList(
      shortUrl: string,
      remoteDir?: string,
      page?: number
    ): Promise<any>;
    fileDiff(): Promise<any>;
    genPanToken(): Promise<any>;
    getHomeInfo(): Promise<any>;
    download(fs_ids: number[]): Promise<any>;
    getFileMeta(remote_file_list: string[]): Promise<FileMeta>;
    getRecentUploads(page?: number): Promise<any>;
    getPublicKey(): Promise<any>;
  }

  export default TeraBoxApp;
}
declare module "@chahakshah/terabox-api/helper" {
  export function getChunkSize(fileSize: number, is_vip?: boolean): number;
  export function hashFile(
    filePath: string
  ): Promise<import("@chahakshah/terabox-api").FileHashData>;
  export function uploadChunks(
    app: import("@chahakshah/terabox-api").default,
    data: import("@chahakshah/terabox-api").UploadData,
    filePath: string,
    maxTasks?: number,
    maxTries?: number
  ): Promise<{ ok: boolean; data: import("@chahakshah/terabox-api").UploadData }>;
  export function unwrapErrorMessage(err: any): string | undefined;
}

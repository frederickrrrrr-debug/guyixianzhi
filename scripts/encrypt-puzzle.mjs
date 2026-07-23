#!/usr/bin/env node

/**
 * 谜题内容加密工具
 * ==================
 *
 * 这个脚本仅供维护者在修改谜题答案或加密内容时运行。网页运行时不会加载它，
 * 并且它不依赖任何第三方 npm 包。
 *
 * 加密方式必须与仓库根目录的 puzzle-crypto.js 保持一致：
 *
 *   1. 将 challengeId、一个 NUL 字符和玩家输入拼接起来；
 *   2. 对拼接结果计算 SHA-256，得到 256 位 AES 密钥；
 *   3. 使用仓库约定的固定 IV，通过 AES-256-GCM 加密内容；
 *   4. 将“密文 + 16 字节 GCM 认证标签”编码为 Base64。
 *
 * 最终只需把脚本输出的 Base64 字符串复制到 puzzle-data.js。谜题答案和
 * 待加密正文不应写入 puzzle-data.js，也不应提交为其他明文配置文件。
 *
 * 输入参数
 * --------
 *
 * --id <challengeId>
 *   谜题的唯一 ID，例如 archive-gw 或 timeline-calibration。
 *   每段密文必须使用不同的 challengeId。由于项目使用固定 IV，不要用同一个
 *   challengeId 加密两段不同内容。即使旧密文已从当前文件删除，它通常仍会
 *   留在 Git 历史中；修改正文后应换一个新 ID，例如 archive-gw-v2，并同步
 *   修改页面解密时使用的 ID。
 *
 * --input <玩家输入>
 *   玩家需要输入的答案。可以重复传入多次；多段输入会用 NUL 字符连接。
 *
 *   普通密码只需要一个 --input：
 *     --input 3461
 *
 *   登录凭证需要两个 --input，顺序必须与网页一致：
 *     --input <员工编号> --input <员工密钥>
 *
 *   上例会派生自：
 *     challengeId + "\\0" + 员工编号 + "\\0" + 员工密钥
 *
 * --text <内容>
 *   直接加密一小段文本，例如登录成功后的目标页面路径，或答案正确后才允许
 *   加载的图片路径。
 *
 * --file <文件路径>
 *   从 UTF-8 文件读取要加密的内容，适合多行 HTML 档案正文。
 *   --text 和 --file 必须且只能提供一个。
 *
 * --name <属性名>
 *   可选。提供后，输出会采用可直接复制到 puzzle-data.js 对象中的形式：
 *     archiveGw: "Base64密文"
 *   不提供时只输出 Base64 密文本身。
 *
 * 运行示例
 * --------
 *
 * 1. 四位档案密码，正文保存在临时 HTML 文件中：
 *
 *   node scripts/encrypt-puzzle.mjs \
 *     --id archive-gw \
 *     --input 3461 \
 *     --file /tmp/archive-gw.html \
 *     --name archiveGw
 *
 * 2. 时间谜题。网页会把各数字规范化并用冒号连接：
 *
 *   node scripts/encrypt-puzzle.mjs \
 *     --id timeline-calibration-image-v1 \
 *     --input 2009:4:12:17:2 \
 *     --text image/xs.jpg \
 *     --name timelineCalibration
 *
 * 3. 人数统计谜题。顺序必须与页面中的年份顺序一致：
 *
 *   node scripts/encrypt-puzzle.mjs \
 *     --id ritual-stats-image-v1 \
 *     --input 6:5:2:3:16 \
 *     --text image/xs2.jpg \
 *     --name ritualStats
 *
 * 4. 员工编号和密钥是两段输入，脚本会自动用 NUL 字符连接：
 *
 *   node scripts/encrypt-puzzle.mjs \
 *     --id login-employee-1-target-v1 \
 *     --input "943851198907209213" \
 *     --input "YH82-GS71-LH36-CV94" \
 *     --text level2-1.html \
 *     --name loginEmployee1
 *
 *   node scripts/encrypt-puzzle.mjs \
 *     --id login-employee-2-target-v1 \
 *     --input "灁㵒瘞軎禷禩䫻䫹" \
 *     --input "G7s9-kR2p-Bt4n-Qm6z" \
 *     --text level3-1.html \
 *     --name loginEmployee2
 *
 * 查看内置帮助：
 *
 *   node scripts/encrypt-puzzle.mjs --help
 */

import fs from 'node:fs';
import crypto from 'node:crypto';

// 必须与 puzzle-crypto.js 中的 FIXED_IV 完全一致。
const FIXED_IV = Buffer.from([
    71, 85, 89, 73, 88, 73, 65, 78, 90, 72, 73, 1
]);

const HELP = `
用法：
  node scripts/encrypt-puzzle.mjs [参数]

必需参数：
  --id <challengeId>     唯一的谜题 ID
  --input <玩家输入>     玩家答案；可重复，用 NUL 字符连接
  --text <内容>          直接加密文本
  --file <文件路径>      加密 UTF-8 文件内容

  --text 和 --file 必须且只能提供一个。

可选参数：
  --name <属性名>        输出 puzzle-data.js 对象属性格式
  --help                 显示帮助
`.trim();

function fail(message) {
    console.error(`错误：${message}\n`);
    console.error(HELP);
    process.exit(1);
}

function readOptionValue(args, index, option) {
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--')) {
        fail(`${option} 后面缺少值`);
    }
    return value;
}

function parseArguments(args) {
    const options = {
        id: null,
        inputs: [],
        text: null,
        file: null,
        name: null
    };

    for (let index = 0; index < args.length; index += 1) {
        const argument = args[index];

        if (argument === '--help') {
            console.log(HELP);
            process.exit(0);
        }

        if (argument === '--id') {
            options.id = readOptionValue(args, index, argument);
            index += 1;
        } else if (argument === '--input') {
            options.inputs.push(readOptionValue(args, index, argument));
            index += 1;
        } else if (argument === '--text') {
            options.text = readOptionValue(args, index, argument);
            index += 1;
        } else if (argument === '--file') {
            options.file = readOptionValue(args, index, argument);
            index += 1;
        } else if (argument === '--name') {
            options.name = readOptionValue(args, index, argument);
            index += 1;
        } else {
            fail(`无法识别参数 ${argument}`);
        }
    }

    if (!options.id) {
        fail('缺少 --id');
    }
    if (options.inputs.length === 0) {
        fail('至少需要一个 --input');
    }
    if ((options.text === null) === (options.file === null)) {
        fail('--text 和 --file 必须且只能提供一个');
    }
    if (options.name && !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(options.name)) {
        fail('--name 必须是有效的 JavaScript 属性名');
    }

    return options;
}

function encrypt(challengeId, playerInput, plaintext) {
    // 浏览器端使用 TextEncoder，因此这里也明确按 UTF-8 计算摘要和加密内容。
    const key = crypto
        .createHash('sha256')
        .update(challengeId + '\0' + playerInput, 'utf8')
        .digest();

    const cipher = crypto.createCipheriv('aes-256-gcm', key, FIXED_IV);
    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
        // Web Crypto 期望认证标签附在密文末尾，默认长度为 16 字节。
        cipher.getAuthTag()
    ]);

    return encrypted.toString('base64');
}

const options = parseArguments(process.argv.slice(2));

// 重复的 --input 用 NUL 字符连接。单个输入不会额外添加分隔符。
const playerInput = options.inputs.join('\0');

let plaintext;
if (options.file !== null) {
    try {
        // 不做 trim，确保多行 HTML 的空白与换行能够原样还原。
        plaintext = fs.readFileSync(options.file, 'utf8');
    } catch (error) {
        fail(`无法读取文件 ${options.file}：${error.message}`);
    }
} else {
    plaintext = options.text;
}

const ciphertext = encrypt(options.id, playerInput, plaintext);

if (options.name) {
    console.log(`${options.name}: ${JSON.stringify(ciphertext)}`);
} else {
    console.log(ciphertext);
}

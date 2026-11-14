import { Buffer } from 'node:buffer';

export const TYPES = Object.freeze({ A: 1, NS: 2, CNAME: 5, PTR: 12, TXT: 16, AAAA: 28, SRV: 33 });
export const TYPE_NAMES = Object.freeze({ 1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 16: 'TXT', 28: 'AAAA', 33: 'SRV' });
export const CLASS_IN = 1;
export const CACHE_FLUSH = 0x8000;
export const SECTIONS = Object.freeze(['answer', 'authority', 'additional']);

const MAX_NAME_LENGTH = 255;
const MAX_POINTER_JUMPS = 64;

export class DnsFormatError extends Error {
  constructor(code, reason, offset = null) {
    super(reason);
    this.name = 'DnsFormatError';
    this.code = code;
    this.reason = reason;
    this.offset = offset;
  }
}

/**
 * Decode a (possibly compressed) DNS name. `encodedEnd` bounds the bytes that
 * belong to the current section (RDLENGTH / whole packet). `packetEnd` bounds
 * pointer targets. A pointer may leave `encodedEnd`, but the label run reached
 * through it must stay inside the packet.
 */
export function decodeName(input, start = 0, options = {}) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const packetEnd = Number.isInteger(options.packetEnd) ? options.packetEnd : buffer.length;
  const encodedEnd = Number.isInteger(options.encodedEnd) ? options.encodedEnd : packetEnd;
  if (start < 0 || start > encodedEnd || encodedEnd > packetEnd) {
    throw new DnsFormatError('NAME_OUT_OF_BOUNDS', '名称起点超出报文边界', start);
  }

  const labels = [];
  const visited = new Set();
  let cursor = start;
  let next = null;
  let jumped = false;
  let jumps = 0;
  let encodedLength = 1;

  for (;;) {
    const limit = jumped ? packetEnd : encodedEnd;
    if (cursor >= packetEnd) {
      throw new DnsFormatError('NAME_OUT_OF_BOUNDS', '名称未结束就超出报文边界', cursor);
    }
    const length = buffer[cursor];

    if (length === 0) {
      if (!jumped) next = cursor + 1;
      break;
    }

    const kind = length & 0xc0;
    if (kind === 0xc0) {
      if (cursor + 1 >= limit) {
        throw new DnsFormatError('NAME_OUT_OF_BOUNDS', '压缩指针越过报文边界', cursor);
      }
      const target = ((length & 0x3f) << 8) | buffer[cursor + 1];
      if (target >= packetEnd) {
        throw new DnsFormatError('NAME_POINTER_OUT_OF_BOUNDS', '压缩指针指向报文之外', cursor);
      }
      if (target < 12) {
        throw new DnsFormatError('NAME_POINTER_INTO_HEADER', '压缩指针指向 DNS 头而不是名称', cursor);
      }
      if (target >= cursor) {
        throw new DnsFormatError('NAME_POINTER_FORWARD', '压缩指针必须指向更早的位置', cursor);
      }
      if (visited.has(target)) {
        throw new DnsFormatError('NAME_POINTER_LOOP', '压缩指针形成循环', cursor);
      }
      jumps += 1;
      if (jumps > MAX_POINTER_JUMPS) {
        throw new DnsFormatError('NAME_POINTER_LOOP', '压缩指针跳转次数过多', cursor);
      }
      visited.add(target);
      if (!jumped) next = cursor + 2;
      encodedLength += 2;
      cursor = target;
      jumped = true;
      continue;
    }

    if (kind !== 0) {
      throw new DnsFormatError('NAME_LABEL_TYPE_UNSUPPORTED', '不支持的名称标签类型', cursor);
    }
    if (cursor + 1 + length > limit) {
      throw new DnsFormatError('NAME_LABEL_OUT_OF_BOUNDS', '名称标签越过边界', cursor);
    }
    const label = buffer.subarray(cursor + 1, cursor + 1 + length);
    labels.push(label);
    encodedLength += 1 + length;
    if (encodedLength - 1 > MAX_NAME_LENGTH) {
      throw new DnsFormatError('NAME_TOO_LONG', '名称长度超过 255 字节', cursor);
    }
    cursor += 1 + length;
    if (!jumped) next = cursor;
  }

  return { labels, next };
}

export function nameToText(name) {
  if (typeof name === 'string') return name;
  if (!name || !Array.isArray(name.labels)) return '';
  if (name.labels.length === 0) return '.';
  return name.labels.map(label => label.toString('utf8')).join('.');
}

/** Encode a presentation-format name (no compression); rejects over-long labels. */
export function encodeName(text) {
  const labels = [];
  const trimmed = String(text).replace(/\.$/, '');
  if (trimmed === '' || trimmed === '.') return Buffer.from([0]);
  for (const label of trimmed.split('.')) {
    const bytes = Buffer.from(label, 'utf8');
    if (bytes.length > 63) throw new Error('名称标签过长');
    labels.push(Buffer.from([bytes.length]), bytes);
  }
  const result = Buffer.concat([...labels, Buffer.from([0])]);
  if (result.length > MAX_NAME_LENGTH) throw new Error('名称过长');
  return result;
}

function readU16(buffer, offset, end) {
  if (offset + 2 > end) throw new DnsFormatError('RDATA_OUT_OF_BOUNDS', '字段越过资源记录边界', offset);
  return buffer.readUInt16BE(offset);
}
function readU32(buffer, offset, end) {
  if (offset + 4 > end) throw new DnsFormatError('RDATA_OUT_OF_BOUNDS', '字段越过资源记录边界', offset);
  return buffer.readUInt32BE(offset);
}

export function readRecordData(buffer, type, start, end) {
  switch (type) {
    case TYPES.A:
      if (end - start !== 4) throw new DnsFormatError('RDATA_LENGTH_MISMATCH', 'A 记录长度不是 4 字节', start);
      return { address: [...buffer.subarray(start, end)].join('.') };
    case TYPES.AAAA: {
      if (end - start !== 16) throw new DnsFormatError('RDATA_LENGTH_MISMATCH', 'AAAA 记录长度不是 16 字节', start);
      const groups = [];
      for (let index = 0; index < 16; index += 2) groups.push(buffer.readUInt16BE(start + index).toString(16));
      return { address: groups.join(':') };
    }
    case TYPES.PTR: {
      const { labels } = decodeName(buffer, start, { packetEnd: buffer.length, encodedEnd: end });
      return { target: nameToText({ labels }) };
    }
    case TYPES.SRV: {
      if (start + 6 > end) throw new DnsFormatError('RDATA_OUT_OF_BOUNDS', 'SRV 记录不完整', start);
      const priority = buffer.readUInt16BE(start);
      const weight = buffer.readUInt16BE(start + 2);
      const port = buffer.readUInt16BE(start + 4);
      const { labels } = decodeName(buffer, start + 6, { packetEnd: buffer.length, encodedEnd: end });
      return { priority, weight, port, target: nameToText({ labels }) };
    }
    case TYPES.TXT: {
      if (start === end) throw new DnsFormatError('RDATA_LENGTH_MISMATCH', 'TXT 记录为空', start);
      const strings = [];
      let cursor = start;
      while (cursor < end) {
        const length = buffer[cursor];
        cursor += 1;
        if (cursor + length > end) throw new DnsFormatError('TXT_STRING_OUT_OF_BOUNDS', 'TXT 字符串越过记录边界', cursor);
        strings.push(buffer.subarray(cursor, cursor + length));
        cursor += length;
      }
      return { strings };
    }
    default:
      return { raw: buffer.subarray(start, end) };
  }
}

/**
 * Parse a DNS message. Damaged records are reported in `rejected` and the rest
 * of the packet still parses; only a broken 12-byte header rejects everything.
 */
export function parseMessage(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (buffer.length < 12) {
    return { ok: false, rejected: [{ scope: 'packet', code: 'HEADER_TOO_SHORT', reason: 'DNS 头不完整', offset: 0 }], records: [] };
  }
  const counts = {
    question: buffer.readUInt16BE(4),
    answer: buffer.readUInt16BE(6),
    authority: buffer.readUInt16BE(8),
    additional: buffer.readUInt16BE(10)
  };
  const total = counts.answer + counts.authority + counts.additional;
  const records = [];
  const rejected = [];
  let cursor = 12;

  try {
    for (let index = 0; index < counts.question; index += 1) {
      const name = decodeName(buffer, cursor, { packetEnd: buffer.length });
      cursor = name.next;
      if (cursor + 4 > buffer.length) throw new DnsFormatError('QUESTION_OUT_OF_BOUNDS', '问题段越过报文边界', cursor);
      cursor += 4;
    }
  } catch (error) {
    rejected.push(reject('question', error));
    return { ok: rejected.length === 0, records, rejected, counts };
  }

  for (const section of SECTIONS) {
    for (let index = 0; index < counts[section]; index += 1) {
      const recordStart = cursor;
      let headerEnd = null;
      try {
        const name = decodeName(buffer, cursor, { packetEnd: buffer.length });
        headerEnd = name.next + 10;
        if (headerEnd > buffer.length) throw new DnsFormatError('RECORD_OUT_OF_BOUNDS', '资源记录头越过报文边界', name.next);
        const type = buffer.readUInt16BE(name.next);
        const recordClass = buffer.readUInt16BE(name.next + 2);
        const ttl = buffer.readUInt32BE(name.next + 4);
        const rdlength = buffer.readUInt16BE(name.next + 8);
        const rdataStart = headerEnd;
        const rdataEnd = rdataStart + rdlength;
        if (rdataEnd > buffer.length) throw new DnsFormatError('RDATA_OUT_OF_BOUNDS', 'RDLENGTH 越过报文边界', rdataStart);
        const data = readRecordData(buffer, type, rdataStart, rdataEnd);
        records.push({
          section,
          name: nameToText(name),
          type,
          typeName: TYPE_NAMES[type] ?? String(type),
          class: recordClass & 0x7fff,
          cacheFlush: (recordClass & CACHE_FLUSH) !== 0,
          ttl,
          data,
          offset: recordStart,
          rdataStart,
          rdataEnd,
          sectionIndex: index
        });
        cursor = rdataEnd;
      } catch (error) {
        rejected.push({ ...reject(section, error), sectionIndex: index, offset: recordStart });
        // A record whose length is known can be skipped; otherwise the rest of
        // the packet has no reliable boundary and stops here.
        if (headerEnd !== null && headerEnd <= buffer.length) {
          const end = headerEnd + buffer.readUInt16BE(headerEnd - 2);
          if (end <= buffer.length) { cursor = end; continue; }
        }
        cursor = buffer.length;
      }
    }
  }

  return { ok: rejected.length === 0, records, rejected, counts };
}

function reject(scope, error) {
  if (error instanceof DnsFormatError) {
    return { scope, code: error.code, reason: error.reason, offset: error.offset };
  }
  return { scope, code: 'RECORD_REJECTED', reason: error?.message ?? '记录无法解析', offset: null };
}

export function parsePacket(input) {
  return parseMessage(input);
}

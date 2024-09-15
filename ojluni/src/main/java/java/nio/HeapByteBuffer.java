/*
 * Copyright (C) 2014 The Android Open Source Project
 * Copyright (c) 2000, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

// -- This file was mechanically generated: Do not edit! -- //
// Android-note: This file is generated by ojluni/src/tools/gensrc_android.sh.

package java.nio;

import java.util.Objects;
import libcore.io.Memory;

/**

 * A read/write HeapByteBuffer.






 */
// Android-changed: Make it final as no subclasses exist.
final class HeapByteBuffer
    extends ByteBuffer
{
    // Android-removed: Removed unused constants.
    /*
    // Cached array base offset
    private static final long ARRAY_BASE_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);

    // Cached array index scale
    private static final long ARRAY_INDEX_SCALE = UNSAFE.arrayIndexScale(byte[].class);
    */

    // For speed these fields are actually declared in X-Buffer;
    // these declarations are here as documentation
    /*

    protected final byte[] hb;
    protected final int offset;

    */
    // Android-removed: Removed MemorySegmentProxy to be supported yet.
    HeapByteBuffer(int cap, int lim) {            // package-private

        // Android-changed: Merge the Read-only buffer class with this Read-Write buffer class.
        // super(-1, 0, lim, cap, new byte[cap], 0);
        this(cap, lim, false);
        /*
        hb = new byte[cap];
        offset = 0;
        */
        // Android-removed: buffer.address is only used by Direct*Buffer.
        // this.address = ARRAY_BASE_OFFSET;




    }


   // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
    private HeapByteBuffer(int cap, int lim, boolean isReadOnly) {
        super(-1, 0, lim, cap, new byte[cap], 0);
        this.isReadOnly = isReadOnly;
    }


    // Android-removed: Removed MemorySegmentProxy to be supported yet.
    HeapByteBuffer(byte[] buf, int off, int len) { // package-private

        // Android-changed: Merge the Read-only buffer class with this Read-Write buffer class.
        // super(-1, off, off + len, buf.length, buf, 0);
        this(buf, off, len, false);
        /*
        hb = buf;
        offset = 0;
        */
        // Android-removed: buffer.address is only used by Direct*Buffer.
        // this.address = ARRAY_BASE_OFFSET;




    }


   // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
    private HeapByteBuffer(byte[] buf, int off, int len, boolean isReadOnly) {
        super(-1, off, off + len, buf.length, buf, 0);
        this.isReadOnly = isReadOnly;
    }


    // Android-changed: Merge the Read-only buffer class with this Read-Write buffer class.
    // Android-changed: Make the method private.
    // Android-removed: Removed MemorySegmentProxy to be supported yet.
    private HeapByteBuffer(byte[] buf,
                                   int mark, int pos, int lim, int cap,
                                   int off, boolean isReadOnly)
    {

        super(mark, pos, lim, cap, buf, off);
        // Android-changed: Merge the Read-only buffer class with this Read-Write buffer class.
        this.isReadOnly = isReadOnly;
        /*
        hb = buf;
        offset = off;
        */
        // Android-removed: buffer.address is only used by Direct*Buffer.
        // this.address = ARRAY_BASE_OFFSET + off * ARRAY_INDEX_SCALE;




    }

    public ByteBuffer slice() {
        int pos = this.position();
        int lim = this.limit();
        int rem = (pos <= lim ? lim - pos : 0);
        return new HeapByteBuffer(hb,
                -1,
                0,
                rem,
                rem,
        // Android-removed: Removed MemorySegmentProxy not supported yet.
                pos + offset,
        // Android-changed: Merge the Read-only buffer class with this Read-Write buffer class.
                isReadOnly);
    }

    @Override
    public ByteBuffer slice(int index, int length) {
        Objects.checkFromIndexSize(index, length, limit());
        return new HeapByteBuffer(hb,
                -1,
                0,
                length,
                length,
        // Android-removed: Removed MemorySegmentProxy not supported yet.
                index + offset,
        // Android-changed: Merge the Read-only buffer class with this Read-Write buffer class.
                isReadOnly);
    }

    public ByteBuffer duplicate() {
        return new HeapByteBuffer(hb,
                this.markValue(),
                this.position(),
                this.limit(),
                this.capacity(),
        // Android-removed: Removed MemorySegmentProxy not supported yet.
                offset,
        // Android-changed: Merge the Read-only buffer class with this Read-Write buffer class.
                isReadOnly);
    }

    public ByteBuffer asReadOnlyBuffer() {

        // Android-removed: Removed MemorySegmentProxy not supported yet.
        // Android-changed: Merge the Read-only buffer class with this Read-Write buffer class.
        /*
        return new HeapByteBufferR(hb,
                                     this.markValue(),
                                     this.position(),
                                     this.limit(),
                                     this.capacity(),
                                     offset, segment);
        */
        return new HeapByteBuffer(hb,
                this.markValue(),
                this.position(),
                this.limit(),
                this.capacity(),
                offset,
                true /* isReadOnly */);



    }



    // Android-changed:  Make it private as no subclasses exist.
    private int ix(int i) {
        return i + offset;
    }


    private long byteOffset(long i) {
        return address + i;
    }


    @Override
    public byte get() {
        return hb[ix(nextGetIndex())];
    }

    @Override
    public byte get(int i) {
        return hb[ix(checkIndex(i))];
    }








    @Override
    public ByteBuffer get(byte[] dst, int offset, int length) {
        checkScope();
        Objects.checkFromIndexSize(offset, length, dst.length);
        int pos = position();
        if (length > limit() - pos)
            throw new BufferUnderflowException();
        System.arraycopy(hb, ix(pos), dst, offset, length);
        position(pos + length);
        return this;
    }

    @Override
    public ByteBuffer get(int index, byte[] dst, int offset, int length) {
        checkScope();
        Objects.checkFromIndexSize(index, length, limit());
        Objects.checkFromIndexSize(offset, length, dst.length);
        System.arraycopy(hb, ix(index), dst, offset, length);
        return this;
    }

    public boolean isDirect() {
        return false;
    }



    @Override
    public boolean isReadOnly() {
        // Android-changed: Merge the Read-only buffer class with this Read-Write buffer class.
        return isReadOnly;
    }

    @Override
    public ByteBuffer put(byte x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        hb[ix(nextPutIndex())] = x;
        return this;



    }

    @Override
    public ByteBuffer put(int i, byte x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        hb[ix(checkIndex(i))] = x;
        return this;



    }

    @Override
    public ByteBuffer put(byte[] src, int offset, int length) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        checkScope();
        Objects.checkFromIndexSize(offset, length, src.length);
        int pos = position();
        if (length > limit() - pos)
            throw new BufferOverflowException();
        System.arraycopy(src, offset, hb, ix(pos), length);
        position(pos + length);
        return this;



    }

    @Override
    public ByteBuffer put(ByteBuffer src) {

        checkScope();

        // Android-note: The super class speed-up this operation with Memory.memmove, and arraycopy.
        super.put(src);


























        return this;



    }

    @Override
    public ByteBuffer put(int index, ByteBuffer src, int offset, int length) {

        checkScope();
        super.put(index, src, offset, length);
        return this;



    }

    @Override
    public ByteBuffer put(int index, byte[] src, int offset, int length) {

        checkScope();
        Objects.checkFromIndexSize(index, length, limit());
        Objects.checkFromIndexSize(offset, length, src.length);
        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        System.arraycopy(src, offset, hb, ix(index), length);
        return this;



    }


























    @Override
    public ByteBuffer compact() {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        int pos = position();
        int lim = limit();
        assert (pos <= lim);
        int rem = (pos <= lim ? lim - pos : 0);
        System.arraycopy(hb, ix(pos), hb, ix(0), rem);
        position(rem);
        limit(capacity());
        discardMark();
        return this;



    }





    @Override
    byte _get(int i) {                          // package-private
        return hb[i];
    }

    @Override
    void _put(int i, byte b) {                  // package-private

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        hb[i] = b;



    }

    // char



    @Override
    public char getChar() {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // return SCOPED_MEMORY_ACCESS.getCharUnaligned(scope(), hb, byteOffset(nextGetIndex(2)), bigEndian);
        return getCharUnchecked(nextGetIndex(2));
    }

    @Override
    public char getChar(int i) {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // return SCOPED_MEMORY_ACCESS.getCharUnaligned(scope(), hb, byteOffset(checkIndex(i, 2)), bigEndian);
        return getCharUnchecked(checkIndex(i, 2));
    }



    @Override
    public ByteBuffer putChar(char x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // SCOPED_MEMORY_ACCESS.putCharUnaligned(scope(), hb, byteOffset(nextPutIndex(2)), x, bigEndian);
        putCharUnchecked(nextPutIndex(2), x);
        return this;



    }

    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    char getCharUnchecked(int i) {
        int ix = ix(i);
        byte[] src = hb;
        if (bigEndian) {
            return (char) ((src[ix] << 8) | (src[ix + 1] & 0xff));
        } else {
            return (char) ((src[ix + 1] << 8) | (src[ix] & 0xff));
        }
    }

    @Override
    void getUnchecked(int pos, char[] dst, int dstOffset, int length) {
        Memory.unsafeBulkGet(dst, dstOffset, length * 2, hb, ix(pos), 2, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public ByteBuffer putChar(int i, char x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // SSCOPED_MEMORY_ACCESS.putCharUnaligned(scope(), hb, byteOffset(checkIndex(i, 2)), x, bigEndian);
        putCharUnchecked(checkIndex(i, 2), x);
        return this;



    }

    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    void putCharUnchecked(int i, char x) {
        int ix = ix(i);
        byte[] dst = hb;

        if (bigEndian) {
            dst[ix++] = (byte) ((x >> 8) & 0xff);
            dst[ix  ] = (byte) ((x >> 0) & 0xff);
        } else {
            dst[ix++] = (byte) ((x >> 0) & 0xff);
            dst[ix  ] = (byte) ((x >> 8) & 0xff);
        }
    }

    @Override
    void putUnchecked(int pos, char[] src, int srcOffset, int length) {
        Memory.unsafeBulkPut(hb, ix(pos), length * 2, src, srcOffset, 2, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public CharBuffer asCharBuffer() {
        int pos = position();
        int size = (limit() - pos) >> 1;
        // Android-removed: buffer.address is only used by Direct*Buffer.
        // long addr = address + pos;
        // Android-changed: Merge the big and little endian buffer class.
        /*
        return (bigEndian
                ? (CharBuffer)(new ByteBufferAsCharBufferB(this,
                                                               -1,
                                                               0,
                                                               size,
                                                               size,
                                                               addr, segment))
                : (CharBuffer)(new ByteBufferAsCharBufferL(this,
                                                               -1,
                                                               0,
                                                               size,
                                                               size,
                                                               addr, segment)));
        */
        return new ByteBufferAsCharBuffer(this,
                -1,
                0,
                size,
                size,
                pos,
                order());
    }


    // short



    @Override
    public short getShort() {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // return SCOPED_MEMORY_ACCESS.getShortUnaligned(scope(), hb, byteOffset(nextGetIndex(2)), bigEndian);
        return getShortUnchecked(nextGetIndex(2));
    }

    @Override
    public short getShort(int i) {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // return SCOPED_MEMORY_ACCESS.getShortUnaligned(scope(), hb, byteOffset(checkIndex(i, 2)), bigEndian);
        return getShortUnchecked(checkIndex(i, 2));
    }



    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    short getShortUnchecked(int i) {
        byte[] src = hb;
        int ix = ix(i);
        if (bigEndian) {
            return (short) ((src[ix] << 8) | (src[ix + 1] & 0xff));
        } else {
            return (short) ((src[ix + 1] << 8) | (src[ix] & 0xff));
        }
    }

    @Override
    void getUnchecked(int pos, short[] dst, int dstOffset, int length) {
        Memory.unsafeBulkGet(dst, dstOffset, length * 2, hb, ix(pos), 2, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public ByteBuffer putShort(short x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // SCOPED_MEMORY_ACCESS.putShortUnaligned(scope(), hb, byteOffset(nextPutIndex(2)), x, bigEndian);
        putShortUnchecked(nextPutIndex(2), x);
        return this;



    }

    @Override
    public ByteBuffer putShort(int i, short x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // SCOPED_MEMORY_ACCESS.putShortUnaligned(scope(), hb, byteOffset(checkIndex(i, 2)), x, bigEndian);
        putShortUnchecked(checkIndex(i, 2), x);
        return this;



    }

    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    void putShortUnchecked(int i, short x) {
        byte[] dst = hb;
        int ix = ix(i);
        if (bigEndian) {
            dst[ix++] = (byte) ((x >> 8) & 0xff);
            dst[ix  ] = (byte) ((x >> 0) & 0xff);
        } else {
            dst[ix++] = (byte) ((x >> 0) & 0xff);
            dst[ix  ] = (byte) ((x >> 8) & 0xff);
        }
    }

    @Override
    void putUnchecked(int pos, short[] src, int srcOffset, int length) {
        Memory.unsafeBulkPut(hb, ix(pos), length * 2, src, srcOffset, 2, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public ShortBuffer asShortBuffer() {
        int pos = position();
        int size = (limit() - pos) >> 1;
        // Android-removed: buffer.address is only used by Direct*Buffer.
        // long addr = address + pos;
        // Android-changed: Merge the big and little endian buffer class.
        /*
        return (bigEndian
                ? (ShortBuffer)(new ByteBufferAsShortBufferB(this,
                                                                 -1,
                                                                 0,
                                                                 size,
                                                                 size,
                                                                 addr, segment))
                : (ShortBuffer)(new ByteBufferAsShortBufferL(this,
                                                                 -1,
                                                                 0,
                                                                 size,
                                                                 size,
                                                                 addr, segment)));
        */
        return new ByteBufferAsShortBuffer(this,
                -1,
                0,
                size,
                size,
                pos,
                order());
    }


    // int



    @Override
    public int getInt() {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // return SCOPED_MEMORY_ACCESS.getIntUnaligned(scope(), hb, byteOffset(nextGetIndex(4)), bigEndian);
        return getIntUnchecked(nextGetIndex(4));
    }

    @Override
    public int getInt(int i) {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // return SCOPED_MEMORY_ACCESS.getIntUnaligned(scope(), hb, byteOffset(checkIndex(i, 4)), bigEndian);
        return getIntUnchecked(checkIndex(i, 4));
    }



    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    int getIntUnchecked(int i) {
        int ix = ix(i);
        byte[] src = hb;
        if (bigEndian) {
            return (((src[ix++] & 0xff) << 24) |
                    ((src[ix++] & 0xff) << 16) |
                    ((src[ix++] & 0xff) <<  8) |
                    ((src[ix  ] & 0xff)      ));
        } else {
            return (((src[ix++] & 0xff)      ) |
                    ((src[ix++] & 0xff) <<  8) |
                    ((src[ix++] & 0xff) << 16) |
                    ((src[ix  ] & 0xff) << 24));
        }
    }

    @Override
    void getUnchecked(int pos, int[] dst, int dstOffset, int length) {
        Memory.unsafeBulkGet(dst, dstOffset, length * 4, hb, ix(pos), 4, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public ByteBuffer putInt(int x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // SCOPED_MEMORY_ACCESS.putIntUnaligned(scope(), hb, byteOffset(nextPutIndex(4)), x, bigEndian);
        putIntUnchecked(nextPutIndex(4), x);
        return this;



    }

    @Override
    public ByteBuffer putInt(int i, int x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // SCOPED_MEMORY_ACCESS.putIntUnaligned(scope(), hb, byteOffset(checkIndex(i, 4)), x, bigEndian);
        putIntUnchecked(checkIndex(i, 4), x);
        return this;



    }

    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    void putIntUnchecked(int i, int x) {
        int ix = ix(i);
        byte[] dst = hb;

        if (bigEndian) {
            dst[ix++] = (byte) ((x >> 24) & 0xff);
            dst[ix++] = (byte) ((x >> 16) & 0xff);
            dst[ix++] = (byte) ((x >>  8) & 0xff);
            dst[ix  ] = (byte) ((x      ) & 0xff);
        } else {
            dst[ix++] = (byte) ((x      ) & 0xff);
            dst[ix++] = (byte) ((x >>  8) & 0xff);
            dst[ix++] = (byte) ((x >> 16) & 0xff);
            dst[ix  ] = (byte) ((x >> 24) & 0xff);
        }
    }

    @Override
    void putUnchecked(int pos, int[] src, int srcOffset, int length) {
        Memory.unsafeBulkPut(hb, ix(pos), length * 4, src, srcOffset, 4, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public IntBuffer asIntBuffer() {
        int pos = position();
        int size = (limit() - pos) >> 2;
        // Android-removed: buffer.address is only used by Direct*Buffer.
        // long addr = address + pos;
        // Android-changed: Merge the big and little endian buffer class.
        /*
        return (bigEndian
                ? (IntBuffer)(new ByteBufferAsIntBufferB(this,
                                                             -1,
                                                             0,
                                                             size,
                                                             size,
                                                             addr, segment))
                : (IntBuffer)(new ByteBufferAsIntBufferL(this,
                                                             -1,
                                                             0,
                                                             size,
                                                             addr, segment)));
        */
        return new ByteBufferAsIntBuffer(this,
                -1,
                0,
                size,
                size,
                pos,
                order());
    }


    // long



    @Override
    public long getLong() {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // return SCOPED_MEMORY_ACCESS.getLongUnaligned(scope(), hb, byteOffset(nextGetIndex(8)), bigEndian);
        return getLongUnchecked(nextGetIndex(8));
    }

    @Override
    public long getLong(int i) {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // return SCOPED_MEMORY_ACCESS.getLongUnaligned(scope(), hb, byteOffset(checkIndex(i, 8)), bigEndian);
        return getLongUnchecked(checkIndex(i, 8));
    }



    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    long getLongUnchecked(int i) {
        int ix = ix(i);
        byte[] src = hb;

        if (bigEndian) {
            int h = ((src[ix++] & 0xff) << 24) |
                    ((src[ix++] & 0xff) << 16) |
                    ((src[ix++] & 0xff) <<  8) |
                    ((src[ix++] & 0xff) <<  0);
            int l = ((src[ix++] & 0xff) << 24) |
                    ((src[ix++] & 0xff) << 16) |
                    ((src[ix++] & 0xff) <<  8) |
                    ((src[ix  ] & 0xff) <<  0);
            return (((long) h) << 32L) | (((long) l) & 0xffffffffL);
        } else {
            int l = ((src[ix++] & 0xff) <<  0) |
                    ((src[ix++] & 0xff) <<  8) |
                    ((src[ix++] & 0xff) << 16) |
                    ((src[ix++] & 0xff) << 24);
            int h = ((src[ix++] & 0xff) <<  0) |
                    ((src[ix++] & 0xff) <<  8) |
                    ((src[ix++] & 0xff) << 16) |
                    ((src[ix  ] & 0xff) << 24);
            return (((long) h) << 32L) | (((long) l) & 0xffffffffL);
        }
    }

    @Override
    void getUnchecked(int pos, long[] dst, int dstOffset, int length) {
        Memory.unsafeBulkGet(dst, dstOffset, length * 8, hb, ix(pos), 8, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public ByteBuffer putLong(long x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // SCOPED_MEMORY_ACCESS.putLongUnaligned(scope(), hb, byteOffset(nextPutIndex(8)), x, bigEndian);
        putLongUnchecked(nextPutIndex(8), x);
        return this;



    }

    @Override
    public ByteBuffer putLong(int i, long x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // SCOPED_MEMORY_ACCESS.putLongUnaligned(scope(), hb, byteOffset(checkIndex(i, 8)), x, bigEndian);
        putLongUnchecked(checkIndex(i, 8), x);
        return this;



    }

    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    void putLongUnchecked(int i, long x) {
        int ix = ix(i);
        byte[] dst = hb;
        if (bigEndian) {
            int t = (int) (x >> 32);
            dst[ix++] = (byte) ((t >> 24) & 0xff);
            dst[ix++] = (byte) ((t >> 16) & 0xff);
            dst[ix++] = (byte) ((t >>  8) & 0xff);
            dst[ix++] = (byte) ((t >>  0) & 0xff);
            t = (int) x;
            dst[ix++] = (byte) ((t >> 24) & 0xff);
            dst[ix++] = (byte) ((t >> 16) & 0xff);
            dst[ix++] = (byte) ((t >>  8) & 0xff);
            dst[ix  ] = (byte) ((t >>  0) & 0xff);
        } else {
            int t = (int) x;
            dst[ix++] = (byte) ((t >>  0) & 0xff);
            dst[ix++] = (byte) ((t >>  8) & 0xff);
            dst[ix++] = (byte) ((t >> 16) & 0xff);
            dst[ix++] = (byte) ((t >> 24) & 0xff);
            t = (int) (x >> 32);
            dst[ix++] = (byte) ((t >>  0) & 0xff);
            dst[ix++] = (byte) ((t >>  8) & 0xff);
            dst[ix++] = (byte) ((t >> 16) & 0xff);
            dst[ix  ] = (byte) ((t >> 24) & 0xff);
        }
    }

    @Override
    void putUnchecked(int pos, long[] src, int srcOffset, int length) {
        Memory.unsafeBulkPut(hb, ix(pos), length * 8, src, srcOffset, 8, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public LongBuffer asLongBuffer() {
        int pos = position();
        int size = (limit() - pos) >> 3;
        // Android-removed: buffer.address is only used by Direct*Buffer.
        // long addr = address + pos;
        // Android-changed: Merge the big and little endian buffer class.
        /*
        return (bigEndian
                ? (LongBuffer)(new ByteBufferAsLongBufferB(this,
                                                               -1,
                                                               0,
                                                               size,
                                                               size,
                                                               addr, segment))
                : (LongBuffer)(new ByteBufferAsLongBufferL(this,
                                                               -1,
                                                               0,
                                                               size,
                                                               size,
                                                               addr, segment)));
        */
        return new ByteBufferAsLongBuffer(this,
                -1,
                0,
                size,
                size,
                pos,
                order());
    }


    // float



    @Override
    public float getFloat() {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // int x = SCOPED_MEMORY_ACCESS.getIntUnaligned(scope(), hb, byteOffset(nextGetIndex(4)), bigEndian);
        // return Float.intBitsToFloat(x);
        return getFloatUnchecked(nextGetIndex(4));
    }

    @Override
    public float getFloat(int i) {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // int x = SCOPED_MEMORY_ACCESS.getIntUnaligned(scope(), hb, byteOffset(checkIndex(i, 4)), bigEndian);
        // return Float.intBitsToFloat(x);
        return getFloatUnchecked(checkIndex(i, 4));
    }



    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    float getFloatUnchecked(int i) {
        return Float.intBitsToFloat(getIntUnchecked(i));
    }

    @Override
    void getUnchecked(int pos, float[] dst, int dstOffset, int length) {
        Memory.unsafeBulkGet(dst, dstOffset, length * 4, hb, ix(pos), 4, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public ByteBuffer putFloat(float x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // int y = Float.floatToRawIntBits(x);
        // SCOPED_MEMORY_ACCESS.putIntUnaligned(scope(), hb, byteOffset(nextPutIndex(4)), y, bigEndian);
        putFloatUnchecked(nextPutIndex(4), x);
        return this;



    }

    @Override
    public ByteBuffer putFloat(int i, float x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // int y = Float.floatToRawIntBits(x);
        // SCOPED_MEMORY_ACCESS.putIntUnaligned(scope(), hb, byteOffset(checkIndex(i, 4)), y, bigEndian);
        putFloatUnchecked(checkIndex(i, 4), x);
        return this;



    }

    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    void putFloatUnchecked(int i, float x) {
        putIntUnchecked(i, Float.floatToRawIntBits(x));
    }

    @Override
    void putUnchecked(int pos, float[] src, int srcOffset, int length) {
        Memory.unsafeBulkPut(hb, ix(pos), length * 4, src, srcOffset, 4, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public FloatBuffer asFloatBuffer() {
        int pos = position();
        int size = (limit() - pos) >> 2;
        // Android-removed: buffer.address is only used by Direct*Buffer.
        // long addr = address + pos;
        // Android-changed: Merge the big and little endian buffer class.
        /*
        return (bigEndian
                ? (FloatBuffer)(new ByteBufferAsFloatBufferB(this,
                                                                 -1,
                                                                 0,
                                                                 size,
                                                                 size,
                                                                 addr, segment))
                : (FloatBuffer)(new ByteBufferAsFloatBufferL(this,
                                                                 -1,
                                                                 0,
                                                                 size,
                                                                 size,
                                                                 addr, segment)));
        */
        return new ByteBufferAsFloatBuffer(this,
                -1,
                0,
                size,
                size,
                pos,
                order());
    }


    // double



    @Override
    public double getDouble() {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // long x = SCOPED_MEMORY_ACCESS.getLongUnaligned(scope(), hb, byteOffset(nextGetIndex(8)), bigEndian);
        // return Double.longBitsToDouble(x);
        return getDoubleUnchecked(nextGetIndex(8));
    }

    @Override
    public double getDouble(int i) {
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // long x = SCOPED_MEMORY_ACCESS.getLongUnaligned(scope(), hb, byteOffset(checkIndex(i, 8)), bigEndian);
        // return Double.longBitsToDouble(x);
        return getDoubleUnchecked(checkIndex(i, 8));
    }



    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    double getDoubleUnchecked(int i) {
        return Double.longBitsToDouble(getLongUnchecked(i));
    }

    @Override
    void getUnchecked(int pos, double[] dst, int dstOffset, int length) {
        Memory.unsafeBulkGet(dst, dstOffset, length * 8, hb, ix(pos), 8, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public ByteBuffer putDouble(double x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // long y = Double.doubleToRawLongBits(x);
        // SCOPED_MEMORY_ACCESS.putLongUnaligned(scope(), hb, byteOffset(nextPutIndex(8)), y, bigEndian);
        putDoubleUnchecked(nextPutIndex(8), x);
        return this;



    }

    @Override
    public ByteBuffer putDouble(int i, double x) {

        // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
        throwIfReadOnly();
        // Android-changed: Avoid unsupported ScopedMemoryAccess.
        // long y = Double.doubleToRawLongBits(x);
        // SCOPED_MEMORY_ACCESS.putLongUnaligned(scope(), hb, byteOffset(checkIndex(i, 8)), y, bigEndian);
        putDoubleUnchecked(checkIndex(i, 8), x);
        return this;



    }

    // BEGIN Android-added: {get,put}*Unchecked() accessors.
    @Override
    void putDoubleUnchecked(int i, double x) {
        putLongUnchecked(i, Double.doubleToRawLongBits(x));
    }

    @Override
    void putUnchecked(int pos, double[] src, int srcOffset, int length) {
        Memory.unsafeBulkPut(hb, ix(pos), length * 8, src, srcOffset, 8, !nativeByteOrder);
    }
    // END Android-added: {get,put}*Unchecked() accessors.

    @Override
    public DoubleBuffer asDoubleBuffer() {
        int pos = position();
        int size = (limit() - pos) >> 3;
        // Android-removed: buffer.address is only used by Direct*Buffer.
        // long addr = address + pos;
        // Android-changed: Merge the big and little endian buffer class.
        /*
        return (bigEndian
                ? (DoubleBuffer)(new ByteBufferAsDoubleBufferB(this,
                                                                   -1,
                                                                   0,
                                                                   size,
                                                                   size,
                                                                   addr, segment))
                : (DoubleBuffer)(new ByteBufferAsDoubleBufferL(this,
                                                                   -1,
                                                                   0,
                                                                   size,
                                                                   size,
                                                                   addr, segment)));
        */
        return new ByteBufferAsDoubleBuffer(this,
                -1,
                0,
                size,
                size,
                pos,
                order());
    }
















































    // Android-added: Merge the Read-only buffer class with this Read-Write buffer class.
    private void throwIfReadOnly() {
        if (isReadOnly) {
            throw new ReadOnlyBufferException();
        }
    }
}

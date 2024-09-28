/*
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

/*
 * This file is available under and governed by the GNU General Public
 * License version 2 only, as published by the Free Software Foundation.
 * However, the following notice accompanied the original version of this
 * file:
 *
 * Written by Doug Lea with assistance from members of JCP JSR-166
 * Expert Group and released to the public domain, as explained at
 * http://creativecommons.org/publicdomain/zero/1.0/
 */


package java.util.concurrent;

@SuppressWarnings({"unchecked", "deprecation", "all"})
public class DelayQueue<E extends java.util.concurrent.Delayed> extends java.util.AbstractQueue<E> implements java.util.concurrent.BlockingQueue<E> {

public DelayQueue() { throw new RuntimeException("Stub!"); }

public DelayQueue(java.util.Collection<? extends E> c) { throw new RuntimeException("Stub!"); }

public boolean add(E e) { throw new RuntimeException("Stub!"); }

public void clear() { throw new RuntimeException("Stub!"); }

public int drainTo(java.util.Collection<? super E> c) { throw new RuntimeException("Stub!"); }

public int drainTo(java.util.Collection<? super E> c, int maxElements) { throw new RuntimeException("Stub!"); }

public java.util.Iterator<E> iterator() { throw new RuntimeException("Stub!"); }

public boolean offer(E e) { throw new RuntimeException("Stub!"); }

public boolean offer(E e, long timeout, java.util.concurrent.TimeUnit unit) { throw new RuntimeException("Stub!"); }

public E peek() { throw new RuntimeException("Stub!"); }

public E poll() { throw new RuntimeException("Stub!"); }

public E poll(long timeout, java.util.concurrent.TimeUnit unit) throws java.lang.InterruptedException { throw new RuntimeException("Stub!"); }

public void put(E e) { throw new RuntimeException("Stub!"); }

public int remainingCapacity() { throw new RuntimeException("Stub!"); }

@android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_OPENJDK_21_V1_APIS)
public E remove() { throw new RuntimeException("Stub!"); }

public boolean remove(java.lang.Object o) { throw new RuntimeException("Stub!"); }

public int size() { throw new RuntimeException("Stub!"); }

public E take() throws java.lang.InterruptedException { throw new RuntimeException("Stub!"); }

public java.lang.Object[] toArray() { throw new RuntimeException("Stub!"); }

public <T> T[] toArray(T[] a) { throw new RuntimeException("Stub!"); }
}


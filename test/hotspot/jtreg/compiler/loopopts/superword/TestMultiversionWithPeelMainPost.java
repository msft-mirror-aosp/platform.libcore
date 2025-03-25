/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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

package compiler.loopopts.superword;

/*
 * @test
 * @bug 8352587
 * @summary Test case where we used to Multiversion a PeelMainPost loop,
 *          which is useless and triggered an assert later on.
 * @run main compiler.loopopts.superword.TestMultiversionWithPeelMainPost
 * @run main/othervm -XX:CompileCommand=compileonly,compiler.loopopts.superword.TestMultiversionWithPeelMainPost::test
 *                   -XX:-TieredCompilation -Xcomp
 *                   -XX:PerMethodTrapLimit=0
 *                   compiler.loopopts.superword.TestMultiversionWithPeelMainPost
 */

public class TestMultiversionWithPeelMainPost {
    static byte byArr[] = new byte[2];

    public static void main(String[] strArr) {
        test();
    }

    static void test() {
        int x = 2;
        int i = 4;
        while (i > 0) {
            for (int j = 5; j < 56; j++) {
                byArr[1] = 3;
            }
            for (int j = 256; j > 3; j -= 2) {
                x += 3;
            }
            i--;
        }
    }
}

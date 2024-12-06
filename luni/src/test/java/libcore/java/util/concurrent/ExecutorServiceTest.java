/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package libcore.java.util.concurrent;

import static org.junit.Assert.assertTrue;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ExecutorServiceTest {

    private static class TestRunnable implements Runnable {
        public void run() { }
    }

    @Test
    public void testClose() {
        final ExecutorService e = Executors.newWorkStealingPool();
        try {
            e.execute(new TestRunnable());
            e.execute(new TestRunnable());
            e.execute(new TestRunnable());
        } finally {
            e.close();
        }
        assertTrue(e.isTerminated());
    }
}

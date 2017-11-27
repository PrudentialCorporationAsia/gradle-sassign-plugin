/*
 * Copyright 2017 Prudential Corporation Asia
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package hk.com.prudential.gradle.sassign.util;


import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A utility class to get properties etc from Gradle
 */
public class GradleIntegrationUtil {
    private static Logger logger = LoggerFactory.getLogger(GradleIntegrationUtil.class);

    /**
     * Get the set of properties from the Gradle runtime
     * @return The Gradle properties
     */
    public static Properties getProperties() {
        Properties p = System.getProperties();
        for (Object k: p.keySet()) {
            logger.info("property: {} -> {}", k.toString(), p.getProperty(k.toString(), ""));
        }
        return p;
    }

}

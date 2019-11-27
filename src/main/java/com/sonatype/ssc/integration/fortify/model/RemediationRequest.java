/*
 * Copyright (c) 2016-present Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.sonatype.ssc.integration.fortify.model;
/*
{
        "packageUrl":"pkg:maven/tomcat/tomcat-util@5.5.23?type=jar"
}

 */

public class RemediationRequest
{
  private String packageUrl;

  public String getPackageUrl()
  {
    return packageUrl;
  }

  public void setPackageUrl(String packageUrl)
  {
    this.packageUrl = packageUrl;
  }

  @Override
  public String toString()
  {
    return "RemediationRequest [packageUrl = " + packageUrl + "]";
  }

  public String toJSONString()
  {
    return "{\"packageUrl\":\"" + packageUrl +  "\"}";
  }
}

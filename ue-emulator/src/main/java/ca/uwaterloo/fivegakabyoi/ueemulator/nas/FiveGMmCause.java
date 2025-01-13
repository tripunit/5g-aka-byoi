// Copyright (c) 2024-2025 Julian Parkin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package ca.uwaterloo.fivegakabyoi.ueemulator.nas;

public enum FiveGMmCause
{
    ILLEGAL_UE                         ( 3, "Illegal UE"                                  ),
    TRACKING_AREA_NOT_ALLOWED          (12, "Tracking area not allowed"                   ),
    MAC_FAILURE                        (20, "MAC failure"                                 ),
    SYNCH_FAILURE                      (21, "Synch failure"                               ),
    NON_5G_AUTHENTICATION_UNACCEPTABLE (26, "Non-5G authentication unacceptable"          ),
    MESSAGE_TYPE_NON_EXISTENT          (97, "Message type non-existent or not implemented");

    private final int    value;
    private final String name;

    public int    getValue() { return value; }
    public String getName()  { return name;  }

    private FiveGMmCause(int value, String name)
    {
        this.value = value;
        this.name  = name;
    }
}

import os
import json
import sys

def process_data(data, config, logger, db, cache, validator, formatter, output):
    result = []
    for item in data:
        if item.get("active"):
            if item.get("type") == "A":
                if item.get("value") > 100:
                    if validator.check(item):
                        result.append(formatter.format(item))
                    else:
                        result.append(item)
                else:
                    result.append(item)
            elif item.get("type") == "B":
                result.append(item)
            else:
                for sub in item.get("children", []):
                    if sub.get("valid"):
                        result.append(sub)
    return result


def transform_data(data, config, logger, db, cache, validator, formatter, output):
    result = []
    for item in data:
        if item.get("active"):
            if item.get("type") == "A":
                if item.get("value") > 100:
                    if validator.check(item):
                        result.append(formatter.format(item))
                    else:
                        result.append(item)
                else:
                    result.append(item)
            elif item.get("type") == "B":
                result.append(item)
            else:
                for sub in item.get("children", []):
                    if sub.get("valid"):
                        result.append(sub)
    return result


def unused_helper():
    return "never called"


class GodObject:
    def m1(self): pass
    def m2(self): pass
    def m3(self): pass
    def m4(self): pass
    def m5(self): pass
    def m6(self): pass
    def m7(self): pass
    def m8(self): pass
    def m9(self): pass
    def m10(self): pass
    def m11(self): pass
    def m12(self): pass
    def m13(self): pass
    def m14(self): pass
    def m15(self): pass
    def m16(self): pass
    def m17(self): pass
    def m18(self): pass
    def m19(self): pass
    def m20(self): pass
    def m21(self): pass

##################################################
# file: CompetitionService_types.py
#
# schema types generated by "ZSI.generate.wsdl2python.WriteServiceModule"
#    /usr/bin/wsdl2py -bw http://redalert3pc.comp.pubsvs.gamespy.com/competitionservice/competitionservice.asmx?wsdl
#
##################################################

import ZSI
import ZSI.TCcompound
from ZSI.schema import LocalElementDeclaration, ElementDeclaration, TypeDefinition, GTD, GED
from ZSI.generate.pyclass import pyclass_type

##############################
# targetNamespace
# http://gamespy.net/competition/
##############################

class ns0:
    targetNamespace = "http://gamespy.net/competition/"

    class LoginCertificate_Def(ZSI.TCcompound.ComplexType, TypeDefinition):
        schema = "http://gamespy.net/competition/"
        type = (schema, "LoginCertificate")
        def __init__(self, pname, ofwhat=(), attributes=None, extend=False, restrict=False, **kw):
            ns = ns0.LoginCertificate_Def.schema
            TClist = [ZSI.TCnumbers.Iint(pname=(ns,"length"), aname="_length", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"version"), aname="_version", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"partnercode"), aname="_partnercode", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"namespaceid"), aname="_namespaceid", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"userid"), aname="_userid", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"profileid"), aname="_profileid", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"expiretime"), aname="_expiretime", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"profilenick"), aname="_profilenick", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"uniquenick"), aname="_uniquenick", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"cdkeyhash"), aname="_cdkeyhash", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.HexBinaryString(pname=(ns,"peerkeymodulus"), aname="_peerkeymodulus", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.HexBinaryString(pname=(ns,"peerkeyexponent"), aname="_peerkeyexponent", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.HexBinaryString(pname=(ns,"serverdata"), aname="_serverdata", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.HexBinaryString(pname=(ns,"signature"), aname="_signature", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            self.attribute_typecode_dict = attributes or {}
            if extend: TClist += ofwhat
            if restrict: TClist = ofwhat
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, pname=pname, inorder=0, **kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._length = None
                    self._version = None
                    self._partnercode = None
                    self._namespaceid = None
                    self._userid = None
                    self._profileid = None
                    self._expiretime = None
                    self._profilenick = None
                    self._uniquenick = None
                    self._cdkeyhash = None
                    self._peerkeymodulus = None
                    self._peerkeyexponent = None
                    self._serverdata = None
                    self._signature = None
                    return
            Holder.__name__ = "LoginCertificate_Holder"
            self.pyclass = Holder

    class CompetitionServiceResponse_Def(ZSI.TCcompound.ComplexType, TypeDefinition):
        schema = "http://gamespy.net/competition/"
        type = (schema, "CompetitionServiceResponse")
        def __init__(self, pname, ofwhat=(), attributes=None, extend=False, restrict=False, **kw):
            ns = ns0.CompetitionServiceResponse_Def.schema
            TClist = [ZSI.TCnumbers.IunsignedInt(pname=(ns,"result"), aname="_result", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"message"), aname="_message", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"csid"), aname="_csid", minOccurs=1, maxOccurs=1, nillable=True, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"ccid"), aname="_ccid", minOccurs=1, maxOccurs=1, nillable=True, typed=False, encoded=kw.get("encoded"))]
            self.attribute_typecode_dict = attributes or {}
            if extend: TClist += ofwhat
            if restrict: TClist = ofwhat
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, pname=pname, inorder=0, **kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._result = None
                    self._message = None
                    self._csid = None
                    self._ccid = None
                    return
            Holder.__name__ = "CompetitionServiceResponse_Holder"
            self.pyclass = Holder

    class CreateSession_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "CreateSession"
        schema = "http://gamespy.net/competition/"
        def __init__(self, **kw):
            ns = ns0.CreateSession_Dec.schema
            TClist = [GTD("http://gamespy.net/competition/","LoginCertificate",lazy=False)(pname=(ns,"certificate"), aname="_certificate", minOccurs=1, maxOccurs=1, nillable=True, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"proof"), aname="_proof", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"gameid"), aname="_gameid", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Ishort(pname=(ns,"platformid"), aname="_platformid", minOccurs=1, maxOccurs=1, nillable=True, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = (u'http://gamespy.net/competition/', u'CreateSession')
            kw["aname"] = "_CreateSession"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._certificate = None
                    self._proof = None
                    self._gameid = None
                    self._platformid = None
                    return
            Holder.__name__ = "CreateSession_Holder"
            self.pyclass = Holder

    class CreateSessionResponse_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "CreateSessionResponse"
        schema = "http://gamespy.net/competition/"
        def __init__(self, **kw):
            ns = ns0.CreateSessionResponse_Dec.schema
            TClist = [GTD("http://gamespy.net/competition/","CompetitionServiceResponse",lazy=False)(pname=(ns,"CreateSessionResult"), aname="_CreateSessionResult", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = (u'http://gamespy.net/competition/', u'CreateSessionResponse')
            kw["aname"] = "_CreateSessionResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._CreateSessionResult = None
                    return
            Holder.__name__ = "CreateSessionResponse_Holder"
            self.pyclass = Holder

    class CreateMatchlessSession_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "CreateMatchlessSession"
        schema = "http://gamespy.net/competition/"
        def __init__(self, **kw):
            ns = ns0.CreateMatchlessSession_Dec.schema
            TClist = [GTD("http://gamespy.net/competition/","LoginCertificate",lazy=False)(pname=(ns,"certificate"), aname="_certificate", minOccurs=1, maxOccurs=1, nillable=True, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"proof"), aname="_proof", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"gameid"), aname="_gameid", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Ishort(pname=(ns,"platformid"), aname="_platformid", minOccurs=1, maxOccurs=1, nillable=True, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = (u'http://gamespy.net/competition/', u'CreateMatchlessSession')
            kw["aname"] = "_CreateMatchlessSession"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._certificate = None
                    self._proof = None
                    self._gameid = None
                    self._platformid = None
                    return
            Holder.__name__ = "CreateMatchlessSession_Holder"
            self.pyclass = Holder

    class CreateMatchlessSessionResponse_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "CreateMatchlessSessionResponse"
        schema = "http://gamespy.net/competition/"
        def __init__(self, **kw):
            ns = ns0.CreateMatchlessSessionResponse_Dec.schema
            TClist = [GTD("http://gamespy.net/competition/","CompetitionServiceResponse",lazy=False)(pname=(ns,"CreateMatchlessSessionResult"), aname="_CreateMatchlessSessionResult", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = (u'http://gamespy.net/competition/', u'CreateMatchlessSessionResponse')
            kw["aname"] = "_CreateMatchlessSessionResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._CreateMatchlessSessionResult = None
                    return
            Holder.__name__ = "CreateMatchlessSessionResponse_Holder"
            self.pyclass = Holder

    class SetReportIntention_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "SetReportIntention"
        schema = "http://gamespy.net/competition/"
        def __init__(self, **kw):
            ns = ns0.SetReportIntention_Dec.schema
            TClist = [GTD("http://gamespy.net/competition/","LoginCertificate",lazy=False)(pname=(ns,"certificate"), aname="_certificate", minOccurs=1, maxOccurs=1, nillable=True, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"proof"), aname="_proof", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"csid"), aname="_csid", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"ccid"), aname="_ccid", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"gameid"), aname="_gameid", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.Boolean(pname=(ns,"authoritative"), aname="_authoritative", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = (u'http://gamespy.net/competition/', u'SetReportIntention')
            kw["aname"] = "_SetReportIntention"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._certificate = None
                    self._proof = None
                    self._csid = None
                    self._ccid = None
                    self._gameid = None
                    self._authoritative = None
                    return
            Holder.__name__ = "SetReportIntention_Holder"
            self.pyclass = Holder

    class SetReportIntentionResponse_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "SetReportIntentionResponse"
        schema = "http://gamespy.net/competition/"
        def __init__(self, **kw):
            ns = ns0.SetReportIntentionResponse_Dec.schema
            TClist = [GTD("http://gamespy.net/competition/","CompetitionServiceResponse",lazy=False)(pname=(ns,"SetReportIntentionResult"), aname="_SetReportIntentionResult", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = (u'http://gamespy.net/competition/', u'SetReportIntentionResponse')
            kw["aname"] = "_SetReportIntentionResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._SetReportIntentionResult = None
                    return
            Holder.__name__ = "SetReportIntentionResponse_Holder"
            self.pyclass = Holder

    class SubmitReport_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "SubmitReport"
        schema = "http://gamespy.net/competition/"
        def __init__(self, **kw):
            ns = ns0.SubmitReport_Dec.schema
            TClist = [GTD("http://gamespy.net/competition/","LoginCertificate",lazy=False)(pname=(ns,"certificate"), aname="_certificate", minOccurs=1, maxOccurs=1, nillable=True, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"proof"), aname="_proof", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"csid"), aname="_csid", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"ccid"), aname="_ccid", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TCnumbers.Iint(pname=(ns,"gameid"), aname="_gameid", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.Boolean(pname=(ns,"authoritative"), aname="_authoritative", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = (u'http://gamespy.net/competition/', u'SubmitReport')
            kw["aname"] = "_SubmitReport"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._certificate = None
                    self._proof = None
                    self._csid = None
                    self._ccid = None
                    self._gameid = None
                    self._authoritative = None
                    return
            Holder.__name__ = "SubmitReport_Holder"
            self.pyclass = Holder

    class SubmitReportResponse_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "SubmitReportResponse"
        schema = "http://gamespy.net/competition/"
        def __init__(self, **kw):
            ns = ns0.SubmitReportResponse_Dec.schema
            TClist = [GTD("http://gamespy.net/competition/","CompetitionServiceResponse",lazy=False)(pname=(ns,"SubmitReportResult"), aname="_SubmitReportResult", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = (u'http://gamespy.net/competition/', u'SubmitReportResponse')
            kw["aname"] = "_SubmitReportResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._SubmitReportResult = None
                    return
            Holder.__name__ = "SubmitReportResponse_Holder"
            self.pyclass = Holder

# end class ns0 (tns: http://gamespy.net/competition/)

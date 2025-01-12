from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import wkst
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class SMBWKST:
	def __init__(self):
		self.service_pipename = r'\wkssvc'
		self.service_uuid = wkst.MSRPC_UUID_WKST
		self.service_manager = None
		
		self.dce = None
		self.handle = None
		
		self.domain_ids = {} #sid to RPC_SID
		self.domain_handles = {} #handle to sid
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = SMBWKST()
			service.dce = connection
			
			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P 
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(service.service_uuid)
			if err is not None:
				raise err
				
			return service, None
		except Exception as e:
			return False, e
	
	@staticmethod
	async def from_smbconnection(connection:SMBConnection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		"""
		Creates the connection to the service using an established SMBConnection.
		This connection will use the given SMBConnection as transport layer.
		"""
		try:
			if auth_level is None:
				#for SMB connection no extra auth needed
				auth_level = RPC_C_AUTHN_LEVEL_NONE
			rpctransport = SMBDCEFactory(connection, filename=SMBWKST().service_pipename)		
			service, err = await SMBWKST.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e

	async def close(self):
		try:
			if self.dce:
				try:
					await self.dce.disconnect()
				except:
					pass
				return
			
			return True,None
		except Exception as e:
			return None, e

	async def list_sessions(self, level = 1):
		level_name = 'Level%s' % level
		status = NTStatus.MORE_ENTRIES
		while status == NTStatus.MORE_ENTRIES:
			resp, err = await wkst.hNetrWkstaUserEnum(self.dce, level)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					yield None, None, err
					return
				resp = err.get_packet()

			if level == 1:
				for entry in resp['UserInfo']['WkstaUserInfo'][level_name]['Buffer']:
					username = entry['wkui1_username'][:-1]
					logondomain = entry['wkui1_logon_domain'][:-1]					
					yield username, logondomain, None
			
			status = NTStatus(resp['ErrorCode'])

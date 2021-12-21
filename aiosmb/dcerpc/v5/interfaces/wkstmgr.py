from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import wkst
from aiosmb.wintypes.ntstatus import NTStatus
		
class SMBWKST:
	def __init__(self, connection):
		self.connection = connection
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
	
	@red
	async def connect(self, open = True):
		rpctransport = SMBDCEFactory(self.connection, filename=r'\wkssvc')
		self.dce = rpctransport.get_dce_rpc()
		await rr(self.dce.connect())
		await rr(self.dce.bind(wkst.MSRPC_UUID_WKST))

		return True,None
	
	@red
	async def close(self):
		if self.dce:
			try:
				await self.dce.disconnect()
			except:
				pass
			return
		
		return True,None

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

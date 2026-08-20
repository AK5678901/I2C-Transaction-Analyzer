from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting

class I2CTransactionHLA(HighLevelAnalyzer):
    exclude_addr = StringSetting(label="Exclude Addresses (e.g. 0x50, 0x60)")

    result_types = {
        'I2C_TA': {
            'format': 'Addr: {{data.addr}} [{{data.rw_mode}}] Payload: {{data.payload}}'
        }
    }

    def __init__(self):
        self.current_tx = None
        self.last_stop_time = None

    def decode(self, frame: AnalyzerFrame):
        frame_type = frame.type.lower()
        
        if frame_type == 'start':
            if self.current_tx is not None:
                self.current_tx['is_repeated'] = True
            else:
                self.current_tx = {
                    'start_time': frame.start_time,
                    'stop_time': None,
                    'addr': "", 'addr_ack': "", 'is_read_op': False, 'w_payload': [],
                    'rep_addr': "", 'rep_addr_ack': "", 'is_rep_read_op': False, 'r_payload': [],
                    'is_repeated': False
                }
        
        elif frame_type == 'address':
            if self.current_tx is not None:
                ack_str = "(A)" if frame.data.get('ack', False) else "(N)"
                is_read = frame.data.get('read', False)
                
                raw_addr = frame.data['address']
                if isinstance(raw_addr, (list, bytes, bytearray)):
                    addr_val = hex(raw_addr[0])
                else:
                    addr_val = hex(raw_addr)
                
                if not self.current_tx['is_repeated']:
                    self.current_tx['addr'] = addr_val
                    self.current_tx['addr_ack'] = ack_str
                    self.current_tx['is_read_op'] = is_read
                else:
                    self.current_tx['rep_addr'] = addr_val
                    self.current_tx['rep_addr_ack'] = ack_str
                    self.current_tx['is_rep_read_op'] = is_read
                    
        elif frame_type == 'data':
            if self.current_tx is not None:
                ack_str = "(A)" if frame.data.get('ack', False) else "(N)"
                data_val = frame.data['data']
                
                if isinstance(data_val, (bytes, bytearray)):
                    data_hex = f"{data_val[0]:02X}"
                elif isinstance(data_val, int):
                    data_hex = f"{data_val:02X}"
                else:
                    data_hex = str(data_val)
                
                payload_str = f"{data_hex}{ack_str}"
                if not self.current_tx['is_repeated']:
                    self.current_tx['w_payload'].append(payload_str)
                else:
                    self.current_tx['r_payload'].append(payload_str)
                    
        elif frame_type == 'stop':
            if self.current_tx is not None:
                self.current_tx['stop_time'] = frame.start_time
                tx = self.current_tx
                self.current_tx = None
                
                return self._process_and_create_frame(tx)
                
        return None

    def _process_and_create_frame(self, tx):
        addr_val = str(tx['addr']).strip()
        rep_addr_val = str(tx.get('rep_addr', '')).strip()

        # 判定部分
        exclude_str = self.exclude_addr.strip() if self.exclude_addr else ""
        if exclude_str:
            # カンマ区切りで分割し、前後の空白を削除してリスト化
            exclude_list = [addr.strip().lower() for addr in exclude_str.split(",")]
            
            if addr_val.lower() in exclude_list or rep_addr_val.lower() in exclude_list:
                self.last_stop_time = tx['stop_time']
                return None

        try:
            start_time = tx['start_time']
            stop_time = tx['stop_time']
            
            # SaleaeTime を Local Timeに変換
            start_dt = start_time.as_datetime().astimezone()
            stop_dt = stop_time.as_datetime().astimezone()
            
            start_utc_str = start_dt.strftime('%Y-%m-%d %H:%M:%S.%f')
            stop_utc_str = stop_dt.strftime('%Y-%m-%d %H:%M:%S.%f')
            
            duration_sec = float(stop_time - start_time)
            duration_us = duration_sec * 1000 * 1000
            
            if self.last_stop_time is not None:
                idle_sec = float(start_time - self.last_stop_time)
                idle_us = idle_sec * 1000 * 1000
            else:
                idle_us = 0.0
        except Exception:
            start_utc_str = ""
            stop_utc_str = ""
            duration_us = 0.0
            idle_us = 0.0

        self.last_stop_time = tx['stop_time']

        rw_mode = "R" if tx['is_read_op'] else "W"
        rep_rw_mode = ("R" if tx['is_rep_read_op'] else "W") if tx['rep_addr'] else ""
        
        payload = " ".join(tx['w_payload'])
        rep_payload = " ".join(tx['r_payload'])

        return AnalyzerFrame(
            'I2C_TA',
            start_time=tx['start_time'],
            end_time=tx['stop_time'],
            data={
                '01_start_time': start_utc_str,    # アルファベット順で先頭に来るようにする
                '02_stop_time': stop_utc_str,
                '03_duration_us': f"{duration_us}",
                '04_idle_time_us': f"{idle_us}",
                '05_addr': tx['addr'],
                '06_rw_mode': rw_mode,
                '07_addr_ack': tx['addr_ack'],
                '08_payload': payload,
                '09_rep_addr': tx['rep_addr'],
                '10_rep_rw_mode': rep_rw_mode,
                '11_rep_addr_ack': tx['rep_addr_ack'],
                '12_rep_payload': rep_payload
            }
        )
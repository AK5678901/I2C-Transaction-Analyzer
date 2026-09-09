from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting

class I2CTransactionHLA(HighLevelAnalyzer):
    exclude_addr = StringSetting(label="Exclude Addresses (e.g. 0x50, 0x60)")

    result_types = {
        'I2C_TA': {
            'format': 'Addr: {{data.05_addr}} [{{data.06_rw_mode}}] Payload: {{data.08_payload}}'
        }
    }

    def __init__(self):
        self.current_tx = None
        self.pending_tx = None
        self.last_stop_time = None

    def decode(self, frame: AnalyzerFrame):
        frame_type = frame.type.lower()
        
        if frame_type == 'start':
            if self.current_tx is not None:
                # ここに入ったらrepeated STARTで次のトランザクションが開始した
                # 直前のトランザクションのstop_timeは、開始したトランザクションのstart_timeとし、送り出す
                self.current_tx['stop_time'] = frame.start_time
                completed_tx = self.current_tx
                self.current_tx = None
                res = self._flush_or_pend(completed_tx)
                # 新しいトランザクションを開始
                self.current_tx = {
                    'start_time': frame.start_time,
                    'stop_time': None,
                    'addr': "", 'addr_ack': "", 'is_read_op': False, 'payload': [],
                    'is_repeated_start': True
                }
                return res
            else:
                self.current_tx = {
                    'start_time': frame.start_time,
                    'stop_time': None,
                    'addr': "", 'addr_ack': "", 'is_read_op': False, 'payload': [],
                    'is_repeated_start': False
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
                
                self.current_tx['addr'] = addr_val
                self.current_tx['addr_ack'] = ack_str
                self.current_tx['is_read_op'] = is_read
                
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
                self.current_tx['payload'].append(payload_str)
                
        elif frame_type == 'stop':
            if self.current_tx is not None:
                self.current_tx['stop_time'] = frame.start_time
                completed_tx = self.current_tx
                self.current_tx = None
                return self._flush_or_pend(completed_tx)
                
        return None

    def _flush_or_pend(self, new_tx):
        # 除外アドレスのチェック
        if new_tx is not None:
            addr_val = str(new_tx['addr']).strip()
            exclude_str = self.exclude_addr.strip() if self.exclude_addr else ""
            if exclude_str:
                exclude_list = [addr.strip().lower() for addr in exclude_str.split(",")]
                if addr_val.lower() in exclude_list:
                    self.last_stop_time = new_tx['stop_time']
                    return None

        output_frame = None
        
        if self.pending_tx is not None:
            prev = self.pending_tx
            curr = new_tx
            
            is_w_then_r = False
            if curr is not None:
                # 「直前がWrite」かつ「今回がRead」かつ「I2Cアドレスが同じ」かを判定
                if not prev['is_read_op'] and curr['is_read_op'] and prev['addr'].lower() == curr['addr'].lower():
                    is_w_then_r = True

            output_frame = self._create_frame(prev, wtr_tx=curr if is_w_then_r else None)
            
            if is_w_then_r:
                self.pending_tx = None
            else:
                self.pending_tx = curr
        else:
            self.pending_tx = new_tx
            
        return output_frame

    def _create_frame(self, tx, wtr_tx=None):
        try:
            start_time = tx['start_time']
            # wtr_txがある場合はstop_timeをReadの終了時刻に合わせる
            stop_time = wtr_tx['stop_time'] if wtr_tx else tx['stop_time']
            
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

        self.last_stop_time = stop_time

        rw_mode = "R" if tx['is_read_op'] else "W"
        payload = " ".join(tx['payload'])
        
        is_rep_str = 'Y' if tx.get('is_repeated_start', False) else ''

        frame_data = {
            '01_start_time': start_utc_str,
            '02_stop_time': stop_utc_str,
            '03_duration_us': f"{duration_us}",
            '04_idle_time_us': f"{idle_us}",
            '05_is_repeated_START': is_rep_str,
            '06_addr': tx['addr'],
            '07_rw_mode': rw_mode,
            '08_addr_ack': tx['addr_ack'],
            '09_payload': payload,
        }

        if wtr_tx is not None:
            wtr_rep_str = 'Y' if wtr_tx.get('is_repeated_start', False) else ''
            frame_data['10_has_write_then_read(WTR)'] = 'Y'
            frame_data['11_WTR_is_repeated_START'] = wtr_rep_str
            frame_data['12_WTR_addr'] = wtr_tx['addr']
            frame_data['13_WTR_rw_mode'] = 'R'
            frame_data['14_WTR_addr_ack'] = wtr_tx['addr_ack']
            frame_data['15_WTR_payload'] = " ".join(wtr_tx['payload'])
        else:
            frame_data['10_has_write_then_read(WTR)'] = ''
            frame_data['11_WTR_is_repeated_START'] = ''
            frame_data['12_WTR_addr'] = ''
            frame_data['13_WTR_rw_mode'] = ''
            frame_data['14_WTR_addr_ack'] = ''
            frame_data['15_WTR_payload'] = ''

        return AnalyzerFrame(
            'I2C_TA',
            start_time=tx['start_time'],
            end_time=stop_time,
            data=frame_data
        )
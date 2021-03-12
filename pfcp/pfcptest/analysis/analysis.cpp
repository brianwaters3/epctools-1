/*
* Copyright (c) 2020 T-Mobile
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <map>

#include "pfcpr15inl.h"
#include "epctools.h"
#include "eutil.h"
#include "ejsonbuilder.h"

#include "pcpp.h"
#include "test.h"

#define PUSH_PACKET_INFO()                                                                   \
   EJsonBuilder::StackObject pushPacket(json);                                               \
   EJsonBuilder::StackUInt pushPacketNumber(json, packetNumber, "packet_number");            \
   EJsonBuilder::StackUInt pushSeqNum(json, appMsg->seqNbr(), "seq_num");

#define PUSH_MSG_INFO(msg)                                                                   \
   EJsonBuilder::StackString pushMsgName(json, #msg, "msg_name");

#define PUSH_SEID()                                                                          \
   EJsonBuilder::StackULongLong pushSeid(json, seid, "seid");                     

// This variant uses pdr_id().rule_id() to get the value
#define PUSH_IES1(msg, action, type)                                                         \
{                                                                                            \
   EJsonBuilder::StackArray push_##action##_##type(json, #action "_" #type);                 \
   for (uint8_t idx = 0u; idx < msg.action##_##type##_count(); ++idx)                        \
   {                                                                                         \
      auto &ie = msg.action##_##type(idx);                                                   \
      EJsonBuilder::StackObject pushIE(json);                                                \
      EJsonBuilder::StackUInt pushIEId(json, ie.type##_id().rule_id(), #type "_id");         \
   }                                                                                         \
}

// This variant uses far_id().far_id_value() to get the value
#define PUSH_IES2(msg, action, type)                                                         \
{                                                                                            \
   EJsonBuilder::StackArray push_##action##_##type(json, #action "_" #type);                 \
   for (uint8_t idx = 0u; idx < msg.action##_##type##_count(); ++idx)                        \
   {                                                                                         \
      auto &ie = msg.action##_##type(idx);                                                   \
      EJsonBuilder::StackObject pushIE(json);                                                \
      EJsonBuilder::StackUInt pushIEId(json, ie.type##_id().type##_id_value(), #type "_id"); \
   }                                                                                         \
}

namespace PFCPTest
{
   namespace analysis
   {
      // This function decodes all the pfcp messages in each pcap in the analysis/pcaps
      // folder and creates output json files with basic information for further analysis
      TEST(analysis_pcaps)
      {
         EString pcapsPath = "./analysis/pcaps";

         // Load pcap tests from disk
         std::set<EString> pcapFiles;
         {
            EDirectory pcapsDir;
            cpStr pcapFile = pcapsDir.getFirstEntry(pcapsPath, "*.pcap");
            while (pcapFile)
            {
               pcapFiles.emplace(pcapFile);
               pcapFile = pcapsDir.getNextEntry();
            }
         }

         // Remove previous results from the pcaps folder
         {
            EDirectory pcapsDir;
            cpStr jsonFile = pcapsDir.getFirstEntry(pcapsPath, "*.json");
            while (jsonFile)
            {
               EString filePath;
               EPath::combine(pcapsPath, jsonFile, filePath);
               if (!EUtility::delete_file(filePath))
                  ELogger::log(LOG_TEST).minor("Couldn't remove file {}", filePath);
               jsonFile = pcapsDir.getNextEntry();
            }
         }

         // Generate json for each pcap
         for (auto pcapFile : pcapFiles)
         {
            EString pcapPath;
            EPath::combine(pcapsPath, pcapFile, pcapPath);

            EJsonBuilder json;
            {
               EJsonBuilder::StackArray pushPackets(json, "packets");

               pcpp::RawPacketVector rawPackets = GetPackets(pcapPath);
               int packetNumber = 1;
               for (auto rawPacket : rawPackets)
               {
                  pcpp::Packet packet(rawPacket);

                  std::vector<uint8_t> payload = ExtractPFCPPayload(packet);
                  std::unique_ptr<PFCP::AppMsg> appMsg = DecodeAppMsg(payload);
                  if (!appMsg)
                  {
                     ELogger::log(LOG_TEST).major("Unhandled PFCP message type in packet {}", packetNumber);
                     ++packetNumber;
                     continue;
                  }

                  switch (appMsg.get()->msgType())
                  {
                     case PFCP_SESS_ESTAB_REQ:
                     {
                        PFCP_R15::SessionEstablishmentReq &sessEstReq = *(static_cast<PFCP_R15::SessionEstablishmentReq *>(appMsg.get()));
                        PUSH_PACKET_INFO()
                        PUSH_MSG_INFO(sess_est_req)

                        auto seid = sessEstReq.cp_fseid().seid();
                        PUSH_SEID()

                        PUSH_IES1(sessEstReq, create, pdr)
                        PUSH_IES2(sessEstReq, create, far)
                        PUSH_IES2(sessEstReq, create, urr)
                        PUSH_IES2(sessEstReq, create, qer)

                        break;
                     }
                     case PFCP_SESS_ESTAB_RSP:
                     {
                        PFCP_R15::SessionEstablishmentRsp &sessEstRsp = *(static_cast<PFCP_R15::SessionEstablishmentRsp *>(appMsg.get()));
                        PUSH_PACKET_INFO()
                        PUSH_MSG_INFO(sess_est_rsp)
                        
                        auto seid = sessEstRsp.up_fseid().seid();
                        PUSH_SEID()

                        break;
                     }
                     case PFCP_SESS_MOD_REQ:
                     {
                        PFCP_R15::SessionModificationReq &sessModReq = *(static_cast<PFCP_R15::SessionModificationReq *>(appMsg.get()));
                        PUSH_PACKET_INFO()
                        PUSH_MSG_INFO(sess_mod_req)

                        auto seid = sessModReq.session()->localSeid();
                        PUSH_SEID()

                        PUSH_IES1(sessModReq, update, pdr)
                        PUSH_IES2(sessModReq, update, far)
                        PUSH_IES2(sessModReq, update, urr)
                        PUSH_IES2(sessModReq, update, qer)
                        PUSH_IES1(sessModReq, create, pdr)
                        PUSH_IES2(sessModReq, create, far)
                        PUSH_IES2(sessModReq, create, urr)
                        PUSH_IES2(sessModReq, create, qer)
                        PUSH_IES1(sessModReq, remove, pdr)
                        PUSH_IES2(sessModReq, remove, far)
                        PUSH_IES2(sessModReq, remove, urr)
                        PUSH_IES2(sessModReq, remove, qer)

                        break;
                     }
                     case PFCP_SESS_MOD_RSP:
                     {
                        PFCP_R15::SessionModificationRsp &sessModRsp = *(static_cast<PFCP_R15::SessionModificationRsp *>(appMsg.get()));
                        PUSH_PACKET_INFO()
                        PUSH_MSG_INFO(sess_mod_rsp)
                        auto seid = sessModRsp.req()->session()->localSeid();
                        PUSH_SEID()
                        break;
                     }
                     case PFCP_SESS_DEL_REQ:
                     {
                        PFCP_R15::SessionDeletionReq &sessDelReq = *(static_cast<PFCP_R15::SessionDeletionReq *>(appMsg.get()));
                        PUSH_PACKET_INFO()
                        PUSH_MSG_INFO(sess_del_req)
                        auto seid = sessDelReq.session()->localSeid();
                        PUSH_SEID()
                        break;
                     }
                     case PFCP_SESS_DEL_RSP:
                     {
                        PFCP_R15::SessionDeletionRsp &sessDelRsp = *(static_cast<PFCP_R15::SessionDeletionRsp *>(appMsg.get()));
                        PUSH_PACKET_INFO()
                        PUSH_MSG_INFO(sess_del_rsp)
                        auto seid = sessDelRsp.req()->session()->localSeid();
                        PUSH_SEID()
                        break;
                     }
                  }

                  ++packetNumber;
               }
            }

            EString jsonName = EPath::getFileNameWithoutExtension(pcapFile) + ".json";
            EString jsonPath;
            EPath::combine(pcapsPath, jsonName, jsonPath);
            std::ofstream jsonFile(jsonPath, std::ios_base::trunc);
            if (jsonFile)
               jsonFile << json.toString() << std::endl;
            jsonFile.close();
         }

         return true;
      }
   } // namespace analysis
} // namespace PFCPTest
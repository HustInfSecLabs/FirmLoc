from transformers import BertTokenizer, BertForMaskedLM, BertModel
from tokenizer import *
import pickle
from torch.utils.data import DataLoader
import os
import torch
import torch.nn as nn
import numpy as np
from tqdm import tqdm
from data import help_tokenize, load_paired_data, FunctionDataset_CL, gen_funcstr
from torch.optim import AdamW
import torch.nn.functional as F
import argparse
import wandb
import logging
import sys
import time
import data
from typing import List, Tuple
import json
WANDB = True

def get_logger(name):
    os.makedirs("logs", exist_ok=True)
    safe = name.replace(os.sep, "_").replace(" ", "_")
    log_path = os.path.join("logs", safe)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        filename=log_path,
    )
    logger = logging.getLogger(__name__)
    s_handle = logging.StreamHandler(sys.stdout)
    s_handle.setLevel(logging.INFO)
    s_handle.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s[:%(lineno)d] - %(message)s"))
    logger.addHandler(s_handle)
    return logger

def eval(model, args, valid_set, logger):

    if WANDB:
        wandb.init(project=f'jTrans-finetune')
        wandb.config.update(args)
    logger.info("Initializing Model...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    #device = torch.device("cuda")
    model.to(device)
    logger.info("Finished Initialization...")
    valid_dataloader = DataLoader(valid_set, batch_size=args.eval_batch_size, num_workers=24, shuffle=True)
    global_steps = 0
    etc=0
    logger.info(f"Doing Evaluation ...")
    mrr = finetune_eval(model, valid_dataloader, device)
    #mrr = finetune_eval(model, valid_dataloader)
    logger.info(f"Evaluate: mrr={mrr}")
    if WANDB:
        wandb.log({
                    'mrr': mrr
                })

def finetune_eval(net, data_loader, device):
    net.eval()
    print(net)
    with torch.no_grad():
        avg=[]
        gt=[]
        cons=[]
        eval_iterator = tqdm(data_loader)
        for i, (seq1,seq2,seq3,mask1,mask2,mask3) in enumerate(eval_iterator):
                input_ids1, attention_mask1= seq1.to(device),mask1.to(device)
                input_ids2, attention_mask2= seq2.to(device),mask2.to(device)
                #input_ids1, attention_mask1= seq1.cuda(),mask1.cuda()
                #input_ids2, attention_mask2= seq2.cuda(),mask2.cuda()
                print(input_ids1.shape)
                print(attention_mask1.shape)
                anchor,pos=0,0

                output=net(input_ids=input_ids1,attention_mask=attention_mask1)
                #anchor=output.last_hidden_state[:,0:1,:]
                anchor=output.pooler_output
                output=net(input_ids=input_ids2,attention_mask=attention_mask2)
                #pos=output.last_hidden_state[:,0:1,:]
                pos=output.pooler_output
                ans=0
                for k in range(len(anchor)):    # check every vector of (vA,vB)
                    vA=anchor[k:k+1].cpu()
                    sim=[]
                    for j in range(len(pos)):
                        vB=pos[j:j+1].cpu()
                        #vB=vB[0]
                        AB_sim=F.cosine_similarity(vA, vB).item()
                        sim.append(AB_sim)
                        if j!=k:
                            cons.append(AB_sim)
                    sim=np.array(sim)
                    y=np.argsort(-sim)
                    posi=0
                    for j in range(len(pos)):
                        if y[j]==k:
                            posi=j+1

                    gt.append(sim[k])

                    ans+=1/posi

                ans=ans/len(anchor)
                avg.append(ans)
                print("now mrr ",np.mean(np.array(avg)))
        fi=open("logft.txt","a")
        print("MRR ",np.mean(np.array(avg)),file=fi)
        print("FINAL MRR ",np.mean(np.array(avg)))
        fi.close()
        return np.mean(np.array(avg))
class BinBertModel(BertModel):
    def __init__(self, config, add_pooling_layer=True):
        super().__init__(config)
        self.config = config
        self.embeddings.position_embeddings=self.embeddings.word_embeddings
from datautils.playdata import DatasetBase as DatasetBase

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="jTrans-EvalSave")
    parser.add_argument("--model_path", type=str, default='./models/jTrans-finetune', help="Path to the model")
    parser.add_argument("--dataset_path", type=str, default='./BinaryCorp/small_test', help="Path to the dataset")
    parser.add_argument("--experiment_path", type=str, default='./experiments/CVE-2022-36480cstecgi.pkl', help="Path to the experiment")
    parser.add_argument("--tokenizer", type=str, default='./jtrans_tokenizer/')
    parser.add_argument("--retrieval", action="store_true", help="Run retrieval mode: embed all funcs in two pkls and output top-k matches")
    parser.add_argument("--a_pkl", type=str, default="", help="Path to A version _extract.pkl")
    parser.add_argument("--b_pkl", type=str, default="", help="Path to B version _extract.pkl")
    parser.add_argument("--a_func_name", type=str, default="", help="Only match this A function name (exact key in A pkl)")
    parser.add_argument("--topk", type=int, default=100, help="Top-k matches to output for each A function")
    parser.add_argument("--retrieval_out", type=str, default="", help="Output text file for top-k results")
    parser.add_argument("--a_emb_out", type=str, default="", help="Output pickle for A embeddings")
    parser.add_argument("--b_emb_out", type=str, default="", help="Output pickle for B embeddings")
    parser.add_argument("--only_emb", action="store_true", help="Only generate .emb.pkl files, skip retrieval/top-k")
    parser.add_argument("--embed_only_pkl", type=str, default="", help="Only embed one extract.pkl and save .emb.pkl")
    parser.add_argument("--embed_only_out", type=str, default="", help="Output .emb.pkl path for single embedding mode")
    
    args = parser.parse_args()

    from datetime import datetime
    now = datetime.now() # current date and time
    TIMESTAMP="%Y%m%d%H%M"
    tim = now.strftime(TIMESTAMP)
    logger = get_logger(f"jTrans-{args.model_path}-eval-{args.dataset_path}_savename_{args.experiment_path}_{tim}")
    logger.info(f"Loading Pretrained Model from {args.model_path} ...")
    model = BinBertModel.from_pretrained(args.model_path)

    model.eval()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")
    #device = torch.device("cuda")
    model.to(device)

    logger.info("Done ...")
    tokenizer = BertTokenizer.from_pretrained(args.tokenizer)
    logger.info("Tokenizer Done ...")
    def load_funcs_from_pkl(pkl_path: str, only_name: str = "") -> Tuple[List[str], List[str]]:
        pkl = pickle.load(open(pkl_path, "rb"))
        names = []
        func_strs = []
        for func_name, func_data in pkl.items():
            if only_name and func_name != only_name:
                continue
            func_addr, asm_list, rawbytes_list, cfg, bai_feature = func_data
            f = (func_addr, asm_list, rawbytes_list, cfg, bai_feature)
            func_str = gen_funcstr(f, convert_jump=True)
            if len(func_str) == 0:
                continue
            names.append(func_name)
            func_strs.append(func_str)
        return names, func_strs

    def embed_func_strs(func_strs: List[str], batch_size: int = 64) -> torch.Tensor:
        embs = []
        for i in tqdm(range(0, len(func_strs), batch_size)):
            batch = func_strs[i:i + batch_size]
            token_seqs = []
            masks = []
            for s in batch:
                ret = help_tokenize(s)
                token_seqs.append(ret["input_ids"])
                masks.append(ret["attention_mask"])
            input_ids = torch.stack(token_seqs, dim=0).to(device)
            attention_mask = torch.stack(masks, dim=0).to(device)
            with torch.no_grad():
                output = model(input_ids=input_ids, attention_mask=attention_mask)
                embs.append(output.pooler_output.detach().cpu())
        return torch.cat(embs, dim=0)
    
    if args.embed_only_pkl:
        logger.info(f"Embedding single pkl: {args.embed_only_pkl}")

        names, func_strs = load_funcs_from_pkl(args.embed_only_pkl)
        emb = embed_func_strs(func_strs)

        emb_out = f"{args.embed_only_pkl}.emb.pkl"
        pickle.dump({"names": names, "emb": emb}, open(emb_out, "wb"))

        logger.info(f"saved embedding: {emb_out}")
        sys.exit(0)

    if args.retrieval:
        if not args.a_pkl or not args.b_pkl:
            raise ValueError("--a_pkl and --b_pkl are required in retrieval mode")

        # 定义对应的 emb 文件路径
        a_emb_path = f"{args.a_pkl}.emb.pkl"
        b_emb_path = f"{args.b_pkl}.emb.pkl"

        # --- 策略：优先加载已存在的 Embedding ---
        if os.path.exists(a_emb_path):
            logger.info(f"Loading PRE-COMPUTED A embeddings from {a_emb_path}")
            a_data = pickle.load(open(a_emb_path, "rb"))
            a_names, a_emb = a_data['names'], a_data['emb']
        else:
            logger.info("A.emb.pkl not found, embedding A functions from scratch...")
            a_names, a_strs = load_funcs_from_pkl(args.a_pkl, args.a_func_name)
            a_emb = embed_func_strs(a_strs)
            # 顺手保存一下，防止下次还要跑
            pickle.dump({"names": a_names, "emb": a_emb}, open(a_emb_path, "wb"))

        if os.path.exists(b_emb_path):
            logger.info(f"Loading PRE-COMPUTED B embeddings from {b_emb_path}")
            b_data = pickle.load(open(b_emb_path, "rb"))
            b_names, b_emb = b_data['names'], b_data['emb']
        else:
            logger.info("B.emb.pkl not found, embedding B functions from scratch...")
            b_names, b_strs = load_funcs_from_pkl(args.b_pkl)
            b_emb = embed_func_strs(b_strs)
            pickle.dump({"names": b_names, "emb": b_emb}, open(b_emb_path, "wb"))
        # ----------------------------------------

        logger.info("Computing top-k matches ...")
        topk = max(1, args.topk)
        
        # 确保在 GPU 上进行矩阵乘法（速度极快）
        a_emb = a_emb.to(device)
        b_emb = b_emb.to(device)
        
        a_norm = torch.nn.functional.normalize(a_emb, dim=1)
        b_norm = torch.nn.functional.normalize(b_emb, dim=1)

        retrieval_out = args.retrieval_out or f"{args.a_pkl}_top{topk}.json"
        results = []
        chunk = 256
        for i in tqdm(range(0, a_norm.size(0), chunk)):
            a_chunk = a_norm[i:i + chunk]
            # 计算余弦相似度矩阵
            sim = torch.matmul(a_chunk, b_norm.t())
            k = min(topk, b_norm.size(0))
            vals, idxs = torch.topk(sim, k=k, dim=1)
            vals = vals.cpu().tolist()
            idxs = idxs.cpu().tolist()
            for row in range(len(idxs)):
                a_name = a_names[i + row]
                matches = []
                for kk in range(len(idxs[row])):
                    b_name = b_names[idxs[row][kk]]
                    score = vals[row][kk]
                    matches.append({"b_name": b_name, "score": float(f"{score:.6f}")})
                results.append({"a_name": a_name, "matches": matches})

        with open(retrieval_out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        logger.info(f"saved top-k results: {retrieval_out}")
        sys.exit(0)

    logger.info("Preparing Datasets ...")
    ft_valid_dataset = FunctionDataset_CL(tokenizer, args.dataset_path, None, True, opt=['O0', 'O1', 'O2', 'O3', 'Os'], add_ebd=True, convert_jump_addr=True)
    for i in tqdm(range(len(ft_valid_dataset.datas))):
        pairs = ft_valid_dataset.datas[i]
        for j in ['O0', 'O1', 'O2', 'O3', 'Os']:
            if ft_valid_dataset.ebds[i].get(j) is not None:
                idx = ft_valid_dataset.ebds[i][j]
                ret1 = tokenizer([pairs[idx]], add_special_tokens=True, max_length=512, padding='max_length', truncation=True, return_tensors='pt') #tokenize them
                seq1 = ret1['input_ids']
                mask1 = ret1['attention_mask']
                input_ids1, attention_mask1= seq1.to(device),mask1.to(device)
                output = model(input_ids=input_ids1, attention_mask=attention_mask1)
                anchor = output.pooler_output
                ft_valid_dataset.ebds[i][j] = anchor.detach().cpu()

    logger.info("ebds start writing")
    fi = open(args.experiment_path, 'wb')
    pickle.dump(ft_valid_dataset.ebds, fi)
    fi.close()

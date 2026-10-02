# SCAPEX 安全威胁建模与缓解措施会签平台

基于 Vue 3、PrimeVue、Pinia、Vue Router、Apollo Client、GraphQL、Vite 与 TypeScript 的独立前端工程。项目不依赖真实后端，GraphQL 查询通过自定义 `ApolloLink` 映射到浏览器 `localStorage` 中的本地仓库。

## 功能

- 系统边界、信任区、组件资产、外部依赖与数据流建模
- 由当前模型状态实时渲染的数据流图
- 威胁、攻击路径、控制、风险与组件/数据流关联
- 未覆盖组件、控制失效、证据缺失、风险接受过期与缓解冲突检查
- 5 x 5 风险矩阵、风险接受条件与有效期
- 开发、安全、业务三方逐项会签
- 会签意见提交时固定审核依据快照（威胁、控制、控制证据、缓解任务）；任一项变化（含证据失效或过期）自动作废受影响的“通过”意见并写明原因，其他角色与其他威胁照常保留
- 版本发布门禁：受影响威胁须开发、安全、业务三端在当前会签轮次一致通过且审核依据全部有效；存在驳回意见或依据失效时停止发布
- 版本快照、版本差异与受影响威胁限定重新审核
- 历史数据升级时按修订号回填审核依据；无法确认依据的历史会签记录标记“待复核”，不计入通过结论
- 控制证据有效期管理、审计轨迹与 Markdown 报告导出
- 全部修改自动持久化到 `localStorage`

## 运行

```bash
npm install
npm run dev
```

默认开发地址为 `http://localhost:18473`。

## 构建

```bash
npm run build
```

## GraphQL

`src/graphql/client.ts` 使用 Apollo Client 的自定义 `ApolloLink`。当前注册以下真实查询操作：

- `DashboardMetrics`
- `ThreatIndex`
- `ControlHealth`

工作台指标通过 Apollo Client 查询，其余业务状态由 Pinia 管理并持久化。

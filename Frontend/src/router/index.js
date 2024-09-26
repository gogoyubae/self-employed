import { createRouter, createWebHistory } from 'vue-router';
import Home from '@/pages/Home.vue';
import Shop from '@/pages/Shop.vue';
import Community from '@/pages/community/Community.vue';
import FloatPopular from '@/pages/InfoPlaza/FloatPopular.vue';
import BoardCreate from '@/pages/community/BoardCreate.vue';
import BoardView from '@/pages/community/BoardView.vue';
import PopularIndustry from '@/pages/InfoPlaza/PopularIndustry.vue';
import TotalTrendingBusinessItems from '@/pages/InfoPlaza/TotalTrendingBusinessItems.vue';
import MylocationTrending from '@/pages/InfoPlaza/MyLocatinTrending.vue';
import CloseRatio from '@/pages/InfoPlaza/CloseRatio.vue';
import StoreInfo from '@/pages/InfoPlaza/StoreInfo.vue';
import PersonalLoan from '@/pages/InfoPlaza/PersonalLoan.vue';
import EnterpriseLoan from '@/pages/InfoPlaza/EnterpriseLoan.vue';
import Education from '@/pages/InfoPlaza/Education.vue';
import Video from '@/pages/InfoPlaza/Video.vue';
import LoanInfo from '@/pages/InfoPlaza/LoanInfo.vue';
import news from '@/pages/InfoPlaza/news.vue';
import Report from '@/pages/simul/Report.vue';
import MyStore from '@/pages/asset/MyStore.vue';
import Mypage from '@/pages/mypage/Mypage.vue';
import StoreReg from '@/pages/asset/StoreReg.vue';
import InfoAgree from '@/pages/asset/InfoAgree.vue';
import AssetSelect from '@/pages/asset/AssetSelect.vue';
import AssetReg from '@/pages/asset/AssetReg.vue';
import AssetFin from '@/pages/asset/AssetFin.vue';
import Simul from '@/pages/simul/Simul.vue';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'Home', component: Home },
    { path: '/shop', name: 'Shop', component: Shop },
    { path: '/community', name: 'Community', component: Community },
    { path: '/community/create', name: 'BoardCreate', component: BoardCreate },
    { path: '/community/view', name: 'BoardView', component: BoardView },
    {
      path: '/infoPlaza/industry',
      name: 'Industry',
      component: PopularIndustry,
    },
    {
      path: '/infoPlaza/industry/totalTrendingBusinessItems',
      name: 'totalTrendingBusinessItems',
      component: TotalTrendingBusinessItems,
    },
    {
      path: '/infoPlaza/industry/mylocationTrending',
      name: 'mylocationTrending',
      component: MylocationTrending,
    },
    {
      path: '/infoPlaza/industry/closeRatio',
      name: 'closeRatio',
      component: CloseRatio,
    },
    {
      path: '/infoPlaza/loanInfo/personalLoan',
      name: 'personalLoan',
      component: PersonalLoan,
    },
    {
      path: '/infoPlaza/loanInfo/enterpriseLoan',
      name: 'enterpriseLoan',
      component: EnterpriseLoan,
    },

    { path: '/infoPlaza/storeInfo', name: 'storeInfo', component: StoreInfo },
    {
      path: '/infoPlaza/floatpopular',
      name: 'FloatPopular',
      component: FloatPopular,
    },
    { path: '/infoPlaza/education', name: 'education', component: Education },
    { path: '/infoPlaza/loanInfo', name: 'loanInfo', component: LoanInfo },
    { path: '/infoPlaza/news', name: 'news', component: news },
    { path: '/infoPlaza/education/video', name: 'video', component: Video },
    { path: '/simul/report', name: 'Report', component: Report },
    { path: '/asset', name: 'MyStore', component: MyStore },
    { path: '/asset/infoagree', name: 'InfoAgree', component: InfoAgree },
    { path: '/asset/assetselect', name: 'AssetSelect', component: AssetSelect },
    { path: '/asset/assetfin', name: 'AssetFin', component: AssetFin },
    { path: '/asset/assetreg', name: 'AssetReg', component: AssetReg },
    { path: '/mypage', name: 'Mypage', component: Mypage },
    { path: '/storereg', name: 'StoreReg', component: StoreReg },
    { path: '/simul', name: 'Simul', component: Simul },
    // { path: '/input', name: "Input", component: Input },
    // { path: '/input2', name: "Input2", component: Input2 },
    // { path: '/update', name: "Update", component: Update },
  ],
});

export default router;
